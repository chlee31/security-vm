import argparse
import ipaddress
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
from collections import deque
from datetime import datetime, timedelta, timezone

import requests
import uvicorn

from app.config import load_config
from app.correlator import Correlator
from app.dashboard import create_app
from app.database import (
    asset_context_for_alert,
    detection_by_id,
    detections_without_ai_reports,
    find_correlated_detection,
    fuse_detection,
    init_db,
    insert_alert,
    insert_app_event,
    insert_detection,
    insert_firewall_block,
    insert_incident_evidence,
    insert_ai_report,
    insert_response,
    insert_sensor_finding,
    ip_enrichment_profile,
    latest_threat_intel_for_ip,
    record_threat_intel_usage,
    sensor_findings_for_detection,
    sensor_finding_detection_id,
    threat_intel_matches,
    upsert_threat_intel_lookup,
    upsert_pending_review,
    zeek_context_for_detection,
    zeek_flow_for_uid,
)
from app.decision_engine import decide
from app.firewall import temporary_block_firewalld
from app.normalizer import detection_type_from_alert, normalize_suricata_event
from app.ai_client import ask_ai_model, build_prompt_audit, check_ai_model, model_metadata, model_run_id
from app.notifications import notify_dangerous_decision
from app.pcap_inventory import list_pcap_files, parse_event_time
from app.risk_score import cap_score
from app.suricata_reader import follow_file, permission_help
from app.sensor_fusion import suricata_finding, zeek_detection, zeek_finding
from app.tshark_summary import summarize_pcap
from app.threat_intel import PRE_AI_PROVIDERS, PROVIDERS, lookup_virustotal_ip, provider_config
from app.threat_intel_worker import run_threat_intel_worker
from app.zeek_ingest import run_zeek_ingest_loop
from app.zeek_inventory import zeek_status


ERROR_MARKERS = (
    "error",
    "exception",
    "traceback",
    "failed",
    "failure",
    "permission denied",
    "no such file",
    "address already in use",
    "cannot",
    "timed out",
    "unreachable",
)


def compact_threat_intel(conn, config, ip_address):
    if not ip_address:
        return None
    active_sources = {
        source for source in PRE_AI_PROVIDERS
        if provider_config(config, source)["enabled"]
    }
    return {
        "local_profile": ip_enrichment_profile(ip_address),
        "matches": [
            match for match in threat_intel_matches(conn, ip_address, "ip")
            if match.get("source") in active_sources
        ],
        "legacy_otx": latest_threat_intel_for_ip(conn, ip_address, "otx") if "otx" in active_sources else None,
    }


def alert_observables(alert):
    try:
        event = json.loads(alert.get("raw_json") or "{}")
    except (TypeError, ValueError):
        return []
    observables = []
    seen = set()

    def add(value, indicator_type):
        value = str(value or "").strip()
        if not value:
            return
        if indicator_type in {"domain", "url"}:
            value = value.lower()
        if indicator_type in {"md5", "sha1_certificate", "sha256"}:
            value = value.lower().replace(":", "")
        key = (value, indicator_type)
        if key not in seen:
            seen.add(key)
            observables.append({"indicator": value, "indicator_type": indicator_type})

    dns = event.get("dns") or {}
    tls = event.get("tls") or {}
    http = event.get("http") or {}
    fileinfo = event.get("fileinfo") or {}
    add(dns.get("rrname"), "domain")
    add(tls.get("sni"), "domain")
    add(tls.get("fingerprint"), "sha1_certificate")
    add(http.get("hostname"), "domain")
    if http.get("hostname") and http.get("url"):
        scheme = "https" if str(alert.get("dest_port") or "") == "443" else "http"
        add(f"{scheme}://{http['hostname']}{http['url']}", "url")
    add(fileinfo.get("md5"), "md5")
    add(fileinfo.get("sha256"), "sha256")
    return observables


def compact_observable_threat_intel(conn, config, alert):
    active_sources = {
        source for source in PRE_AI_PROVIDERS
        if provider_config(config, source)["enabled"]
    }
    results = []
    for observable in alert_observables(alert):
        matches = [
            match for match in threat_intel_matches(
                conn,
                observable["indicator"],
                observable["indicator_type"],
            )
            if match.get("source") in active_sources
        ]
        if matches:
            results.append({**observable, "matches": matches})
    return results


def record_pre_ai_threat_intel_usage(conn, detection_id, alert_id, evidence_context):
    threat_intel = evidence_context.get("threat_intel") or {}
    for side in ("src_ip", "dest_ip"):
        block = threat_intel.get(side) or {}
        indicator = (block.get("local_profile") or {}).get("ip_address")
        for match in block.get("matches") or []:
            record_threat_intel_usage(
                conn,
                detection_id,
                alert_id,
                indicator or match.get("indicator"),
                match.get("indicator_type") or "ip",
                match.get("source") or "unknown",
                "pre_ai_prompt",
                match,
            )
        legacy_otx = block.get("legacy_otx")
        if legacy_otx and indicator:
            record_threat_intel_usage(
                conn,
                detection_id,
                alert_id,
                indicator,
                "ip",
                "otx",
                "pre_ai_prompt",
                legacy_otx,
            )
    for observable in threat_intel.get("alert_observables") or []:
        for match in observable.get("matches") or []:
            record_threat_intel_usage(
                conn,
                detection_id,
                alert_id,
                observable.get("indicator"),
                observable.get("indicator_type") or match.get("indicator_type") or "unknown",
                match.get("source") or "unknown",
                "pre_ai_prompt",
                match,
            )


def parse_lookup_time(value):
    try:
        parsed = datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def verify_dangerous_with_virustotal(conn, config, alert, detection_id, alert_id, ai_report):
    if str(ai_report.get("classification") or "").strip().lower() != "dangerous":
        return []
    settings = provider_config(config, "virustotal")
    if not settings["enabled"] or not settings["api_key"]:
        return []

    ttl_hours = max(1, int(config.get("threat_intel", {}).get("cache_ttl_hours", 24)))
    results = []
    for value in dict.fromkeys([alert.get("src_ip"), alert.get("dest_ip")]):
        if not value:
            continue
        try:
            if not ipaddress.ip_address(value).is_global:
                continue
        except ValueError:
            continue

        cached = latest_threat_intel_for_ip(conn, value, "virustotal")
        cached_at = parse_lookup_time((cached or {}).get("lookup_time"))
        if cached and cached_at and (datetime.now(timezone.utc) - cached_at) < timedelta(hours=ttl_hours):
            result = {**cached, "indicator": value, "source": "virustotal", "cached": True}
        else:
            result = lookup_virustotal_ip(settings, value)
            upsert_threat_intel_lookup(
                conn,
                result["indicator"],
                "virustotal",
                result["reputation"],
                malicious_count=result["malicious_count"],
                suspicious_count=result["suspicious_count"],
                lookup_result=result["lookup_result"],
                raw_response=result["raw_response"],
                alert_id=alert_id,
                detection_id=detection_id,
            )
            result["cached"] = False
        record_threat_intel_usage(
            conn,
            detection_id,
            alert_id,
            value,
            "ip",
            "virustotal",
            "post_ai_verification",
            result,
        )
        results.append(result)
    return results


def safe_filename(value):
    return "".join(char if char.isalnum() or char in ".-_" else "_" for char in str(value))[:160]


def incident_window(config, alert, detection):
    pcap_config = config.get("pcap", {})
    window_minutes = int(pcap_config.get("incident_window_minutes", 5))
    start = parse_event_time(detection.get("first_seen") or alert.get("timestamp"))
    end = parse_event_time(detection.get("last_seen") or alert.get("timestamp")) or start
    if not start:
        return None, None
    return (start - timedelta(minutes=window_minutes)).isoformat(), (end + timedelta(minutes=window_minutes)).isoformat()


def prepare_pcap_evidence(config, alert, detection, alert_id, detection_id):
    pcap_config = config.get("pcap", {})
    inventory = list_pcap_files(
        config,
        detection.get("first_seen") or alert.get("timestamp"),
        detection.get("last_seen") or alert.get("timestamp"),
    )
    related = [file for file in inventory.get("files", []) if file.get("related")]
    max_ai_files = max(0, int(pcap_config.get("max_ai_files", 2)))
    summary_limit = max(1, int(pcap_config.get("summary_packet_limit", 20)))
    summary_timeout = max(1, int(pcap_config.get("summary_timeout_seconds", 20)))
    incident_start, incident_end = incident_window(config, alert, detection)
    summary_dir = Path(pcap_config.get("incident_dir", "/var/log/incidents")) / "summaries" / f"detection-{detection_id}"

    records = []
    summary_sections = []
    for index, file in enumerate(related[:max_ai_files], start=1):
        pcap_path = Path(file.get("path", ""))
        summary_path = summary_dir / f"{index:02d}_{safe_filename(pcap_path.name)}.summary.csv"
        record = {
            "detection_id": detection_id,
            "alert_id": alert_id,
            "incident_start_time": incident_start,
            "incident_end_time": incident_end,
            "incident_pcap_path": str(pcap_path),
            "pcap_summary_path": "",
            "capture_label": file.get("label"),
            "file_size_bytes": file.get("size_bytes"),
            "pcap_modified_at": file.get("modified_at"),
            "summary_status": "not_generated",
            "summary_packet_count": 0,
            "summary_error": "",
            "display_filter": "",
            "ai_sent": False,
            "ai_model_run_id": "",
        }

        try:
            summary = summarize_pcap(
                pcap_path,
                summary_path,
                limit=summary_limit,
                alert=alert,
                timeout=summary_timeout,
            )
            summary_text = Path(summary["path"]).read_text(encoding="utf-8", errors="replace")
            record.update(
                {
                    "pcap_summary_path": summary["path"],
                    "summary_status": summary["status"],
                    "summary_packet_count": summary["packet_count"],
                    "display_filter": summary.get("display_filter", ""),
                }
            )
            summary_sections.append(
                "\n".join(
                    [
                        f"PCAP evidence file {index}",
                        f"capture_label: {file.get('label') or 'capture'}",
                        f"pcap_path: {pcap_path}",
                        f"summary_path: {summary['path']}",
                        f"packet_count: {summary['packet_count']}",
                        f"display_filter: {summary.get('display_filter') or 'none'}",
                        "summary_csv:",
                        summary_text.strip(),
                    ]
                )
            )
        except FileNotFoundError as exc:
            record["summary_status"] = "tshark_unavailable"
            record["summary_error"] = str(exc)
        except subprocess.TimeoutExpired as exc:
            record["summary_status"] = "summary_timeout"
            record["summary_error"] = str(exc)
        except subprocess.CalledProcessError as exc:
            record["summary_status"] = "summary_failed"
            record["summary_error"] = (exc.stderr or exc.stdout or str(exc))[:1000]
        except OSError as exc:
            record["summary_status"] = "summary_failed"
            record["summary_error"] = str(exc)

        records.append(record)

    if summary_sections:
        prompt_summary = "\n\n---\n\n".join(summary_sections)
        packet_summary_status = "generated"
    elif related:
        prompt_summary = ""
        packet_summary_status = "failed"
    else:
        prompt_summary = ""
        packet_summary_status = "no_related_pcaps"

    return {
        "inventory": inventory,
        "related": related,
        "records": records,
        "prompt_summary": prompt_summary,
        "packet_summary_status": packet_summary_status,
        "max_ai_files": max_ai_files,
    }


def compact_pcap_evidence(config, alert, detection=None, pcap_package=None):
    if not pcap_package:
        inventory = list_pcap_files(config, alert.get("timestamp"), alert.get("timestamp"))
        related = [file for file in inventory.get("files", []) if file.get("related")]
        records = []
        packet_summary_status = "not_generated"
        max_ai_files = int(config.get("pcap", {}).get("max_ai_files", 2))
    else:
        inventory = pcap_package.get("inventory", {})
        related = pcap_package.get("related", [])
        records = pcap_package.get("records", [])
        packet_summary_status = pcap_package.get("packet_summary_status", "not_generated")
        max_ai_files = pcap_package.get("max_ai_files")

    summarized_by_path = {record.get("incident_pcap_path"): record for record in records}
    return {
        "status": inventory.get("status"),
        "directory": inventory.get("directory"),
        "window_minutes": inventory.get("window_minutes"),
        "related_file_count": len(related),
        "ai_file_limit": max_ai_files,
        "summarized_file_count": len([record for record in records if record.get("summary_status") == "generated"]),
        "related_files": [
            {
                "name": file.get("name"),
                "label": file.get("label"),
                "size_bytes": file.get("size_bytes"),
                "modified_at": file.get("modified_at"),
                "summary_status": summarized_by_path.get(file.get("path"), {}).get("summary_status"),
                "summary_packet_count": summarized_by_path.get(file.get("path"), {}).get("summary_packet_count"),
                "pcap_summary_path": summarized_by_path.get(file.get("path"), {}).get("pcap_summary_path"),
                "ai_selected": file.get("path") in summarized_by_path,
            }
            for file in related[:5]
        ],
        "packet_summary": packet_summary_status,
        "note": "Raw PCAP bytes are not sent to the AI model; tshark text summaries are sent when generated.",
    }


def build_ai_evidence_context(conn, config, alert, detection=None, pcap_package=None, detection_id=None):
    findings = sensor_findings_for_detection(conn, detection_id) if detection_id else []
    findings = [
        {
            "sensor": item.get("sensor"),
            "sensor_event_id": item.get("sensor_event_id"),
            "finding_type": item.get("finding_type"),
            "finding_name": item.get("finding_name"),
            "severity": item.get("severity"),
            "confidence": item.get("confidence"),
            "community_id": item.get("community_id"),
        }
        for item in findings
    ]
    zeek_context = zeek_context_for_detection(conn, detection_id, seconds=120, limit=50) if detection_id else {"items": []}
    zeek_context = {
        "window_start": zeek_context.get("window_start"),
        "window_end": zeek_context.get("window_end"),
        "items": [
            {
                "log_type": item.get("log_type"),
                "timestamp": item.get("timestamp"),
                "source_ip": item.get("source_ip"),
                "source_port": item.get("source_port"),
                "destination_ip": item.get("destination_ip"),
                "destination_port": item.get("destination_port"),
                "protocol": item.get("protocol"),
                "event_name": item.get("event_name"),
                "message": item.get("message"),
                "sub_message": item.get("sub_message"),
            }
            for item in zeek_context.get("items", [])[:25]
        ],
    }
    return {
        "sensor_fusion": {
            "sensor_state": (detection or {}).get("sensor_state", "suricata_only"),
            "agreement_state": (detection or {}).get("agreement_state", "single_sensor"),
            "correlation_method": (detection or {}).get("correlation_method", "single_sensor"),
            "correlation_confidence": (detection or {}).get("correlation_confidence", 0.5),
            "community_id": (detection or {}).get("community_id"),
            "findings": findings,
        },
        "zeek_context": zeek_context,
        "threat_intel": {
            "policy": "Bulk and cached providers are matched before AI. VirusTotal is excluded here and reserved for post-AI verification of Dangerous classifications.",
            "src_ip": compact_threat_intel(conn, config, alert.get("src_ip")),
            "dest_ip": compact_threat_intel(conn, config, alert.get("dest_ip")),
            "alert_observables": compact_observable_threat_intel(conn, config, alert),
        },
        "pcap_evidence": compact_pcap_evidence(config, alert, detection, pcap_package),
    }


def store_pcap_evidence(conn, pcap_package, report=None, ai_sent=False):
    report = report or {}
    for record in pcap_package.get("records", []):
        record = dict(record)
        record_sent = bool(
            record.get("summary_status") == "generated"
            and (ai_sent or report.get("pcap_summary_included"))
        )
        record["ai_sent"] = record_sent
        record["ai_model_run_id"] = report.get("model_run_id", "") if record_sent else ""
        insert_incident_evidence(conn, record)


def ensure_ai_report_metadata(config, alert, report):
    metadata = model_metadata(config)
    for key, value in metadata.items():
        if not report.get(key):
            report[key] = value
    if not report.get("model_run_id"):
        report["model_run_id"] = model_run_id(metadata, alert)
    return report


def apply_asset_context(detection, asset_context):
    detection["asset_context"] = asset_context
    detection["asset_score_applied"] = asset_context.get("asset_score", 0)
    if detection["asset_score_applied"]:
        detection["python_initial_score"] = cap_score(
            int(detection.get("python_initial_score") or 0) + detection["asset_score_applied"]
        )
    return detection


def attach_asset_context(detection, asset_context):
    detection["asset_context"] = asset_context
    detection["asset_score_applied"] = asset_context.get("asset_score", 0)
    return detection


def assess_detection(conn, config_path, alert, detection, alert_id, detection_id):
    runtime_config = load_config(config_path)
    pcap_package = prepare_pcap_evidence(runtime_config, alert, detection, alert_id, detection_id)
    evidence_context = build_ai_evidence_context(
        conn,
        runtime_config,
        alert,
        detection,
        pcap_package,
        detection_id=detection_id,
    )
    record_pre_ai_threat_intel_usage(conn, detection_id, alert_id, evidence_context)
    ai_sent = False
    try:
        ai_report = ask_ai_model(
            runtime_config,
            alert,
            detection,
            evidence_context=evidence_context,
            pcap_summary=pcap_package["prompt_summary"],
        )
        ai_report = ensure_ai_report_metadata(runtime_config, alert, ai_report)
        ai_sent = True
        insert_app_event(
            conn,
            "info",
            "ai_model",
            f"AI model classified {detection.get('sensor_state', 'sensor')} detection as {ai_report.get('classification', 'Unknown')}",
            {
                "alert_id": alert_id,
                "detection_id": detection_id,
                "sensor_state": detection.get("sensor_state"),
                "elapsed_ms": ai_report.get("elapsed_ms"),
                "confidence": ai_report.get("confidence"),
                "model_identity": ai_report.get("model_identity"),
                "model_run_id": ai_report.get("model_run_id"),
            },
        )
    except requests.RequestException as exc:
        _, prompt_audit = build_prompt_audit(
            runtime_config,
            alert,
            detection,
            evidence_context=evidence_context,
            pcap_summary=pcap_package["prompt_summary"],
        )
        ai_report = {
            **prompt_audit,
            "classification": "Human Review Required",
            "confidence": "Low",
            "risk_adjustment": 0,
            "reason": f"AI model unavailable: {exc}",
            "recommended_action": "human_review",
            "raw_response": "",
            "elapsed_ms": int(runtime_config.get("ai_model", {}).get("timeout_seconds", 90)) * 1000,
        }
        insert_app_event(
            conn,
            "error",
            "ai_model",
            f"AI model unavailable while reviewing detection {detection_id}: {exc}",
            {
                "alert_id": alert_id,
                "detection_id": detection_id,
                "sensor_state": detection.get("sensor_state"),
                "model_identity": ai_report.get("model_identity"),
                "model_run_id": ai_report.get("model_run_id"),
            },
        )
    try:
        ai_report["virustotal_verification"] = verify_dangerous_with_virustotal(
            conn,
            runtime_config,
            alert,
            detection_id,
            alert_id,
            ai_report,
        )
        if ai_report["virustotal_verification"]:
            insert_app_event(
                conn,
                "info",
                "threat_intel",
                f"VirusTotal verified {len(ai_report['virustotal_verification'])} public IP(s) after a Dangerous AI classification",
                {
                    "detection_id": detection_id,
                    "results": [
                        {
                            "indicator": item.get("indicator"),
                            "reputation": item.get("reputation"),
                            "malicious_count": item.get("malicious_count"),
                            "suspicious_count": item.get("suspicious_count"),
                            "cached": item.get("cached"),
                        }
                        for item in ai_report["virustotal_verification"]
                    ],
                },
            )
    except (requests.RequestException, ValueError) as exc:
        ai_report["virustotal_verification"] = []
        insert_app_event(
            conn,
            "error",
            "threat_intel",
            f"VirusTotal post-AI verification failed for detection {detection_id}: {exc}",
        )
    store_pcap_evidence(conn, pcap_package, ai_report, ai_sent=ai_sent)
    insert_ai_report(conn, detection_id, ai_report)

    response = decide(conn, runtime_config, alert, detection, ai_report)
    response["detection_id"] = detection_id
    if response["final_action"] == "temporary_block":
        timeout = runtime_config.get("firewall", {}).get("block_timeout_seconds", 3600)
        status, elapsed_ms, firewall_rule = temporary_block_firewalld(
            response["target_ip"],
            timeout,
            response.get("target_direction") or "source",
        )
        response["response_status"] = status
        response["response_time_ms"] = elapsed_ms
        if status == "blocked":
            insert_firewall_block(
                conn,
                {
                    "detection_id": detection_id,
                    "ip_address": response["target_ip"],
                    "direction": response.get("target_direction"),
                    "reason": f"{response['final_classification']} score={response['final_score']}",
                    "firewall_rule": firewall_rule,
                    "timeout_seconds": timeout,
                    "status": "active",
                    "response_status": status,
                    "response_time_ms": elapsed_ms,
                },
            )

    response_id = insert_response(conn, response)
    response["response_id"] = response_id
    upsert_pending_review(conn, response)
    if (
        response.get("final_classification") == "Dangerous"
        and runtime_config.get("notifications", {}).get("email", {}).get("enabled")
    ):
        notification = notify_dangerous_decision(conn, runtime_config, alert, detection, response, ai_report)
        insert_app_event(
            conn,
            "warning" if notification.get("status") == "failed" else "info",
            "notifications",
            f"Email notification {notification.get('status')}",
            notification,
        )
    insert_app_event(
        conn,
        "info",
        "decision",
        f"{response['final_classification']} action={response['final_action']} score={response['final_score']}",
        {
            "alert_id": alert_id,
            "detection_id": detection_id,
            "sensor_state": detection.get("sensor_state"),
            "target_ip": response.get("target_ip"),
        },
    )
    print(
        f"[{response['final_classification']}] {alert.get('src_ip')} -> {alert.get('dest_ip')} "
        f"{alert.get('signature')} sensor={detection.get('sensor_state')} "
        f"score={response['final_score']} action={response['final_action']}"
    )
    return response


def run_ingest(config_path):
    config = load_config(config_path)
    conn = init_db(config.get("database", {}).get("path", "security_vm.db"))
    correlator = Correlator(config)
    eve_path = config.get("suricata", {}).get("eve_json_path", "/var/log/suricata/eve.json")
    mode = config.get("system", {}).get("mode", "alert_only")
    print(f"[+] Security VM ingest starting in {mode} mode")
    insert_app_event(conn, "info", "ingest", f"Security VM ingest starting in {mode} mode")

    try:
        status = check_ai_model(config)
        insert_app_event(
            conn,
            "info",
            "ai_model",
            f"AI model reachable at {status['host']}",
            {"elapsed_ms": status["elapsed_ms"], "models": status["models"]},
        )
    except requests.RequestException as exc:
        insert_app_event(conn, "error", "ai_model", f"AI model unreachable: {exc}")

    for event in follow_file(eve_path):
        alert = normalize_suricata_event(event)
        if not alert:
            continue

        alert_id = insert_alert(conn, alert)
        alert["alert_id"] = alert_id
        alert["detection_type"] = detection_type_from_alert(alert)
        match, method, confidence = find_correlated_detection(
            conn,
            alert,
            "suricata",
            tolerance_seconds=int(config.get("correlation", {}).get("sensor_time_tolerance_seconds", 10)),
        )
        if match:
            detection_id = match["id"]
            insert_sensor_finding(conn, detection_id, suricata_finding(alert_id, alert))
            detection = fuse_detection(conn, detection_id, alert, method, confidence)
            detection = attach_asset_context(detection, asset_context_for_alert(conn, alert))
        else:
            detection = correlator.correlate(alert, alert_id)
            detection = apply_asset_context(detection, asset_context_for_alert(conn, alert))
            detection_id = insert_detection(conn, detection)
            insert_sensor_finding(conn, detection_id, suricata_finding(alert_id, alert))
        assess_detection(conn, config_path, alert, detection, alert_id, detection_id)


def run_dashboard(config_path, host, port):
    app = create_app(config_path)
    uvicorn.run(app, host=host, port=port)


def run_zeek_status(config_path):
    config = load_config(config_path)
    status = zeek_status(config)
    print(f"Zeek enabled: {status['enabled']}")
    print(f"Zeek interface: {status['interface']}")
    print(f"Zeek installed: {status['installed']}")
    print(f"Zeek running: {status['running']}")
    for name, path in status["binaries"].items():
        print(f"{name}: {path or 'not found'}")
    if status["version"].get("stdout") or status["version"].get("stderr"):
        print(status["version"].get("stdout") or status["version"].get("stderr"))
    if status["zeekctl_status"].get("stdout") or status["zeekctl_status"].get("stderr"):
        print(status["zeekctl_status"].get("stdout") or status["zeekctl_status"].get("stderr"))
    print("Configured logs:")
    for item in status["logs"]:
        if not item.get("accessible", True):
            marker = "permission denied"
        else:
            marker = "exists" if item["exists"] else "missing"
        print(f"  {item['log_type']}: {marker} {item['path']}")


def run_zeek_ingest(config_path):
    config = load_config(config_path)
    conn = init_db(config.get("database", {}).get("path", "security_vm.db"))
    status = zeek_status(config)
    if not config.get("zeek", {}).get("enabled", True):
        print("[+] Zeek ingestion disabled in config")
        insert_app_event(conn, "info", "zeek", "Zeek ingestion disabled in config")
        return
    if not status.get("installed"):
        print("[!] Zeek or zeekctl is not installed. Dashboard will show Zeek unavailable.")
        insert_app_event(conn, "error", "zeek", "Zeek ingestion unavailable: zeek/zeekctl not found", status)
    print(f"[+] Zeek ingest reading JSON logs from {config.get('zeek', {}).get('log_directory')}")

    def process_zeek_event(event_id, event):
        if event.get("log_type") != "notice":
            return
        if sensor_finding_detection_id(conn, "zeek", event_id):
            return
        flow = zeek_flow_for_uid(conn, event.get("zeek_uid")) or {}
        for key in ("source_ip", "source_port", "destination_ip", "destination_port", "protocol", "community_id"):
            if not event.get(key) and flow.get(key) is not None:
                event[key] = flow[key]
        runtime_config = load_config(config_path)
        alert, detection = zeek_detection(event)
        event["detection_type"] = detection.get("detection_type")
        match, method, confidence = find_correlated_detection(
            conn,
            event,
            "zeek",
            tolerance_seconds=int(runtime_config.get("correlation", {}).get("sensor_time_tolerance_seconds", 10)),
        )
        if match:
            detection_id = match["id"]
            insert_sensor_finding(conn, detection_id, zeek_finding(event_id, event))
            detection = fuse_detection(conn, detection_id, event, method, confidence)
            detection = attach_asset_context(detection, asset_context_for_alert(conn, alert))
        else:
            detection = apply_asset_context(detection, asset_context_for_alert(conn, alert))
            detection_id = insert_detection(conn, detection)
            insert_sensor_finding(conn, detection_id, zeek_finding(event_id, event))
        insert_app_event(
            conn,
            "info",
            "sensor_fusion",
            f"Zeek notice entered detection pipeline as {detection.get('sensor_state')}",
            {"zeek_event_id": event_id, "detection_id": detection_id, "correlation_method": detection.get("correlation_method")},
        )
        assess_detection(conn, config_path, alert, detection, None, detection_id)

    run_zeek_ingest_loop(conn, config, on_event=process_zeek_event)


def run_threat_intel(config_path):
    print("[+] Threat-intelligence feed worker starting")
    run_threat_intel_worker(config_path)


def should_show_launcher_line(line):
    lowered = line.lower()
    return any(marker in lowered for marker in ERROR_MARKERS)


def stream_process_output(name, pipe, recent_lines):
    try:
        for raw_line in iter(pipe.readline, ""):
            line = raw_line.rstrip()
            if not line:
                continue
            recent_lines.append(line)
            if should_show_launcher_line(line):
                print(f"[{name}] {line}", flush=True)
    finally:
        pipe.close()


def start_managed_process(name, command, recent_lines):
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    thread = threading.Thread(
        target=stream_process_output,
        args=(name, process.stdout, recent_lines),
        daemon=True,
    )
    thread.start()
    return process, thread


def stop_managed_processes(processes):
    for name, process, _thread, _recent in processes:
        if process.poll() is None:
            print(f"[+] Stopping {name}", flush=True)
            process.terminate()
    for name, process, _thread, _recent in processes:
        if process.poll() is None:
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                print(f"[!] Force stopping {name}", flush=True)
                process.kill()


def print_recent_tail(name, recent_lines):
    if not recent_lines:
        return
    print(f"[!] Recent {name} log tail:", flush=True)
    for line in list(recent_lines)[-12:]:
        print(f"    {line}", flush=True)


def run_quiet_command(name, command, timeout=20):
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as exc:
        print(f"[{name}] {exc}", flush=True)
        return False
    except subprocess.TimeoutExpired:
        print(f"[{name}] command timed out after {timeout} seconds", flush=True)
        return False

    output = "\n".join(part for part in [result.stdout.strip(), result.stderr.strip()] if part)
    if result.returncode != 0:
        print(f"[{name}] exited with code {result.returncode}", flush=True)
        if output:
            for line in output.splitlines()[-12:]:
                print(f"    {line}", flush=True)
        return False
    if output and should_show_launcher_line(output):
        for line in output.splitlines():
            if should_show_launcher_line(line):
                print(f"[{name}] {line}", flush=True)
    return True


def run_all(
    config_path,
    host,
    port,
    external_interface=None,
    internal_interface=None,
    pcap_dir=None,
    restart_suricata=True,
):
    config = load_config(config_path)
    database_path = config.get("database", {}).get("path", "security_vm.db")
    schema_conn = init_db(database_path)
    schema_conn.close()
    print(f"[+] Database schema ready: {database_path}", flush=True)
    pcap_config = config.get("pcap", {})
    external_interface = external_interface or pcap_config.get("external_interface", "ens33")
    internal_interface = internal_interface or pcap_config.get("internal_interface") or config.get("assets", {}).get(
        "internal_interface", "ens37"
    )
    pcap_dir = pcap_dir or pcap_config.get("rolling_dir", "/var/log/pcap")
    project_root = Path(__file__).resolve().parents[1]
    pcap_script = project_root / "scripts" / "start_pcap_capture.sh"

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        eve_path = Path(config.get("suricata", {}).get("eve_json_path", "/var/log/suricata/eve.json"))
        try:
            with eve_path.open("rb"):
                pass
        except (OSError, PermissionError) as exc:
            print(f"[!] Cannot start: {permission_help(eve_path)}", flush=True)
            print(f"[!] Access check: {exc}", flush=True)
            return

    privileged_prefix = []
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("[+] Authenticating once for sensor and packet-capture management", flush=True)
        authorization = subprocess.run(["sudo", "-v"], check=False)
        if authorization.returncode != 0:
            print("[!] Sudo authentication failed; run-all cannot manage the sensors or packet capture.", flush=True)
            return
        privileged_prefix = ["sudo", "-n"]

    commands = [
        (
            "pcap",
            [
                "bash",
                str(pcap_script),
                external_interface,
                internal_interface,
                pcap_dir,
            ],
        ),
        ("ingest", [sys.executable, "-m", "app.main", "ingest", "--config", config_path]),
        ("zeek-ingest", [sys.executable, "-m", "app.main", "zeek-ingest", "--config", config_path]),
        ("threat-intel", [sys.executable, "-m", "app.main", "threat-intel", "--config", config_path]),
        (
            "dashboard",
            [
                sys.executable,
                "-m",
                "app.main",
                "dashboard",
                "--config",
                config_path,
                "--host",
                host,
                "--port",
                str(port),
            ],
        ),
    ]

    processes = []
    shutting_down = False

    def handle_stop(_signum, _frame):
        nonlocal shutting_down
        shutting_down = True
        print("\n[+] Shutdown requested", flush=True)
        stop_managed_processes(processes)

    previous_sigint = signal.getsignal(signal.SIGINT)
    previous_sigterm = signal.getsignal(signal.SIGTERM)
    signal.signal(signal.SIGINT, handle_stop)
    signal.signal(signal.SIGTERM, handle_stop)

    print("[+] Security VM launcher starting", flush=True)
    print(f"[+] Dashboard: http://{host}:{port}/", flush=True)
    print("[+] Normal logs are quiet. Errors and process exits will print here.", flush=True)

    if restart_suricata:
        print("[+] Checking Suricata service", flush=True)
        suricata_active = run_quiet_command(
            "suricata", privileged_prefix + ["systemctl", "is-active", "suricata"], timeout=10
        )
        if not suricata_active:
            print("[+] Starting Suricata", flush=True)
            run_quiet_command(
                "suricata", privileged_prefix + ["systemctl", "start", "suricata"], timeout=60
            )
            run_quiet_command(
                "suricata", privileged_prefix + ["systemctl", "is-active", "suricata"], timeout=10
            )

    if config.get("zeek", {}).get("enabled", True):
        print("[+] Checking Zeek", flush=True)
        status = zeek_status(config)
        if status.get("installed"):
            zeekctl = status.get("binaries", {}).get("zeekctl") or "zeekctl"
            if not status.get("running"):
                run_quiet_command("zeek", privileged_prefix + [zeekctl, "deploy"], timeout=30)
            run_quiet_command("zeek", privileged_prefix + [zeekctl, "status"], timeout=10)
        else:
            print("[zeek] zeek/zeekctl not found; continuing without Zeek", flush=True)

    try:
        for name, command in commands:
            recent_lines = deque(maxlen=40)
            process, thread = start_managed_process(name, command, recent_lines)
            processes.append((name, process, thread, recent_lines))
            print(f"[+] Started {name}", flush=True)

        while not shutting_down:
            for name, process, _thread, recent_lines in processes:
                return_code = process.poll()
                if return_code is not None:
                    shutting_down = True
                    if return_code == 0:
                        print(f"[!] {name} exited", flush=True)
                    else:
                        print(f"[!] {name} exited with code {return_code}", flush=True)
                        print_recent_tail(name, recent_lines)
                    break
            if shutting_down:
                break
            time.sleep(1)
    finally:
        signal.signal(signal.SIGINT, previous_sigint)
        signal.signal(signal.SIGTERM, previous_sigterm)
        stop_managed_processes(processes)


def run_ai_backfill(config_path, limit):
    config = load_config(config_path)
    conn = init_db(config.get("database", {}).get("path", "security_vm.db"))
    metadata = model_metadata(config)
    rows = detections_without_ai_reports(
        conn,
        limit,
        model_identity=metadata["model_identity"],
        ai_profile_uid=metadata.get("ai_profile_uid"),
    )
    print(f"[+] Backfilling AI opinions for {len(rows)} detections")
    insert_app_event(
        conn,
        "info",
        "ai_model",
        f"Starting AI backfill for {len(rows)} detections using {metadata['model_identity']} ({metadata.get('ai_profile_uid')})",
        metadata,
    )

    try:
        status = check_ai_model(config)
        insert_app_event(
            conn,
            "info",
            "ai_model",
            f"AI model reachable at {status['host']}",
            {"elapsed_ms": status["elapsed_ms"], "models": status["models"]},
        )
    except requests.RequestException as exc:
        insert_app_event(conn, "error", "ai_model", f"AI model unreachable before backfill: {exc}")
        print(f"[!] AI model unreachable: {exc}")
        conn.close()
        return

    for row in rows:
        alert = {
            "suricata_event_id": row.get("suricata_event_id"),
            "timestamp": row.get("timestamp"),
            "src_ip": row.get("src_ip"),
            "dest_ip": row.get("dest_ip"),
            "src_port": row.get("src_port"),
            "dest_port": row.get("dest_port"),
            "protocol": row.get("protocol"),
            "signature": row.get("signature"),
            "category": row.get("category"),
            "severity": row.get("severity"),
            "priority": row.get("priority"),
            "flow_id": row.get("flow_id"),
            "community_id": row.get("community_id"),
            "pcap_point": row.get("pcap_point"),
            "raw_json": row.get("raw_json"),
        }
        detection = {
            "first_alert_id": row.get("first_alert_id"),
            "first_seen": row.get("first_seen"),
            "last_seen": row.get("last_seen"),
            "src_ip": row.get("src_ip"),
            "dest_ip": row.get("dest_ip"),
            "src_port": row.get("detection_src_port") or row.get("src_port"),
            "dest_port": row.get("detection_dest_port") or row.get("dest_port"),
            "protocol": row.get("detection_protocol") or row.get("protocol"),
            "community_id": row.get("detection_community_id") or row.get("community_id"),
            "sensor_state": row.get("sensor_state") or "suricata_only",
            "agreement_state": row.get("agreement_state") or "single_sensor",
            "correlation_method": row.get("correlation_method") or "single_sensor",
            "correlation_confidence": row.get("correlation_confidence") or 0.5,
            "detection_type": row.get("detection_type"),
            "alert_count": row.get("alert_count"),
            "unique_dest_ports": row.get("unique_dest_ports"),
            "unique_dest_hosts": row.get("unique_dest_hosts"),
            "time_window_seconds": row.get("time_window_seconds"),
            "mitre_id": row.get("mitre_id"),
            "mitre_name": row.get("mitre_name"),
            "python_initial_score": row.get("python_initial_score"),
            "status": row.get("status"),
        }
        detection = apply_asset_context(detection, asset_context_for_alert(conn, alert))
        pcap_package = prepare_pcap_evidence(config, alert, detection, row["alert_id"], row["detection_id"])
        evidence_context = build_ai_evidence_context(
            conn,
            config,
            alert,
            detection,
            pcap_package,
            detection_id=row["detection_id"],
        )
        record_pre_ai_threat_intel_usage(
            conn,
            row["detection_id"],
            row.get("alert_id"),
            evidence_context,
        )

        try:
            report = ask_ai_model(
                config,
                alert,
                detection,
                evidence_context=evidence_context,
                pcap_summary=pcap_package["prompt_summary"],
            )
            report = ensure_ai_report_metadata(config, alert, report)
            try:
                report["virustotal_verification"] = verify_dangerous_with_virustotal(
                    conn,
                    config,
                    alert,
                    row["detection_id"],
                    row.get("alert_id"),
                    report,
                )
            except (requests.RequestException, ValueError) as exc:
                report["virustotal_verification"] = []
                insert_app_event(
                    conn,
                    "error",
                    "threat_intel",
                    f"VirusTotal post-AI verification failed during backfill for detection {row['detection_id']}: {exc}",
                )
            store_pcap_evidence(conn, pcap_package, report, ai_sent=True)
            insert_ai_report(conn, row["detection_id"], report)
            insert_app_event(
                conn,
                "info",
                "ai_model",
                f"Backfilled detection {row['detection_id']} as {report.get('classification', 'Unknown')}",
                {
                    "detection_id": row["detection_id"],
                    "elapsed_ms": report.get("elapsed_ms"),
                    "model_identity": report.get("model_identity"),
                    "model_run_id": report.get("model_run_id"),
                },
            )
            print(f"[+] detection {row['detection_id']} -> {report.get('classification', 'Unknown')}")
        except requests.RequestException as exc:
            _, prompt_audit = build_prompt_audit(
                config,
                alert,
                detection,
                evidence_context=evidence_context,
                pcap_summary=pcap_package["prompt_summary"],
            )
            store_pcap_evidence(conn, pcap_package, prompt_audit, ai_sent=False)
            insert_app_event(
                conn,
                "error",
                "ai_model",
                f"AI model unavailable while backfilling detection {row['detection_id']}: {exc}",
                {"detection_id": row["detection_id"]},
            )
            print(f"[!] detection {row['detection_id']} failed: {exc}")

    conn.close()


def main():
    parser = argparse.ArgumentParser(description="Security VM application")
    sub = parser.add_subparsers(dest="command", required=True)

    ingest = sub.add_parser("ingest", help="Tail Suricata EVE JSON and process alerts")
    ingest.add_argument("--config", default="config.yaml")

    dashboard = sub.add_parser("dashboard", help="Run dashboard API")
    dashboard.add_argument("--config", default="config.yaml")
    dashboard.add_argument("--host", default="127.0.0.1")
    dashboard.add_argument("--port", default=8000, type=int)

    run_all_parser = sub.add_parser("run-all", help="Start PCAP capture, ingest, and dashboard together")
    run_all_parser.add_argument("--config", default="config.yaml")
    run_all_parser.add_argument("--host", default="0.0.0.0")
    run_all_parser.add_argument("--port", default=8000, type=int)
    run_all_parser.add_argument("--external-interface", default=None)
    run_all_parser.add_argument("--internal-interface", default=None)
    run_all_parser.add_argument("--pcap-dir", default=None)
    run_all_parser.add_argument("--skip-suricata-restart", action="store_true")

    zeek_ingest = sub.add_parser("zeek-ingest", help="Tail Zeek JSON logs and store notice/weird/context events")
    zeek_ingest.add_argument("--config", default="config.yaml")

    zeek_status_parser = sub.add_parser("zeek-status", help="Print Zeek installation and log status")
    zeek_status_parser.add_argument("--config", default="config.yaml")
    threat_intel_parser = sub.add_parser("threat-intel", help="Refresh enabled threat-intelligence feeds on schedule")
    threat_intel_parser.add_argument("--config", default="config.yaml")

    ai_backfill = sub.add_parser("ai-backfill", help="Ask the AI model for opinions on detections without reports")
    ai_backfill.add_argument("--config", default="config.yaml")
    ai_backfill.add_argument("--limit", default=50, type=int)

    args = parser.parse_args()
    if args.command == "ingest":
        run_ingest(args.config)
    elif args.command == "dashboard":
        run_dashboard(args.config, args.host, args.port)
    elif args.command == "run-all":
        run_all(
            args.config,
            args.host,
            args.port,
            external_interface=args.external_interface,
            internal_interface=args.internal_interface,
            pcap_dir=args.pcap_dir,
            restart_suricata=not args.skip_suricata_restart,
        )
    elif args.command == "ai-backfill":
        run_ai_backfill(args.config, args.limit)
    elif args.command == "zeek-ingest":
        run_zeek_ingest(args.config)
    elif args.command == "zeek-status":
        run_zeek_status(args.config)
    elif args.command == "threat-intel":
        run_threat_intel(args.config)


if __name__ == "__main__":
    main()

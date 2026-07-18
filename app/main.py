import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
from collections import deque

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
    insert_ai_assessment,
    insert_ai_report,
    insert_score_breakdown,
    insert_response,
    insert_sensor_finding,
    ip_enrichment_profile,
    latest_threat_intel_for_ip,
    record_threat_intel_usage,
    sensor_findings_for_detection,
    sensor_finding_detection_id,
    threat_intel_matches,
    update_detection_python_score,
    upsert_pending_review,
    zeek_context_for_detection,
    zeek_flow_for_uid,
)
from app.decision_engine import decide, safe_risk_adjustment
from app.normalizer import detection_type_from_alert, normalize_suricata_event
from app.ai_client import ask_ai_model, build_prompt_audit, check_ai_model, model_metadata, model_run_id
from app.risk_score import cap_score, deterministic_score
from app.suricata_reader import follow_file, permission_help
from app.sensor_fusion import suricata_finding, zeek_detection, zeek_finding
from app.threat_intel import (
    FETCHERS,
    PRE_AI_PROVIDERS,
    PROVIDERS,
    ai_provider_status,
    provider_config,
    provider_evidence_for_indicator,
)
from app.threat_intel_worker import run_threat_intel_worker
from app.zeek_ingest import run_zeek_ingest_loop
from app.zeek_inventory import zeek_status
from app.virustotal import verify_dangerous as verify_dangerous_with_virustotal


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
        "indicator": ip_address,
        "indicator_type": "ip",
        "local_profile": ip_enrichment_profile(ip_address),
        "matches": [
            match for match in threat_intel_matches(conn, ip_address, "ip")
            if match.get("source") in active_sources
        ],
        "legacy_otx": latest_threat_intel_for_ip(conn, ip_address, "otx") if "otx" in active_sources else None,
        "providers": provider_evidence_for_indicator(conn, config, ip_address),
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
        results.append(
            {
                **observable,
                "matches": matches,
                "providers": provider_evidence_for_indicator(
                    conn,
                    config,
                    observable["indicator"],
                    observable["indicator_type"],
                ),
            }
        )
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


def build_ai_evidence_context(conn, config, alert, detection=None, detection_id=None):
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
            "timestamp": item.get("finding_timestamp"),
            "source_ip": item.get("source_ip"),
            "source_port": item.get("source_port"),
            "destination_ip": item.get("destination_ip"),
            "destination_port": item.get("destination_port"),
            "protocol": item.get("protocol"),
        }
        for item in findings
    ]
    correlation_config = config.get("correlation", {})
    zeek_context = zeek_context_for_detection(
        conn,
        detection_id,
        seconds=int(correlation_config.get("zeek_context_window_seconds", 120)),
        limit=int(correlation_config.get("zeek_context_limit", 100)),
    ) if detection_id else {"items": [], "summary": {}}
    zeek_context = {
        "window_start": zeek_context.get("window_start"),
        "window_end": zeek_context.get("window_end"),
        "summary": zeek_context.get("summary") or {},
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
            "case_uid": (detection or {}).get("case_uid"),
            "sensor_state": (detection or {}).get("sensor_state", "suricata_only"),
            "agreement_state": (detection or {}).get("agreement_state", "single_sensor"),
            "correlation_method": (detection or {}).get("correlation_method", "single_sensor"),
            "correlation_rule_strength": (detection or {}).get("correlation_confidence", 0.5),
            "correlation_policy_version": correlation_config.get("policy_version", "correlation-v1"),
            "community_id": (detection or {}).get("community_id"),
            "findings": findings,
        },
        "repeated_activity": {
            "finding_count": int((detection or {}).get("alert_count") or len(findings)),
            "unique_destination_ports": int((detection or {}).get("unique_dest_ports") or 0),
            "unique_destination_hosts": int((detection or {}).get("unique_dest_hosts") or 0),
            "window_seconds": int((detection or {}).get("time_window_seconds") or 0),
            "periodicity": (zeek_context.get("summary") or {}).get("periodicity"),
            "average_interval_seconds": (zeek_context.get("summary") or {}).get("average_interval_seconds"),
        },
        "zeek_context": zeek_context,
        "threat_intel": {
            "policy": "Bulk and cached providers are matched before AI. VirusTotal is excluded here and reserved for post-AI verification of Dangerous classifications.",
            "provider_status": ai_provider_status(config, conn),
            "src_ip": compact_threat_intel(conn, config, alert.get("src_ip")),
            "dest_ip": compact_threat_intel(conn, config, alert.get("dest_ip")),
            "alert_observables": compact_observable_threat_intel(conn, config, alert),
        },
    }


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
    evidence_context = build_ai_evidence_context(
        conn,
        runtime_config,
        alert,
        detection,
        detection_id=detection_id,
    )
    findings = sensor_findings_for_detection(conn, detection_id)
    score_breakdown = deterministic_score(
        alert,
        detection,
        findings=findings,
        evidence_context=evidence_context,
    )
    update_detection_python_score(conn, detection_id, score_breakdown["python_score"])
    detection["python_initial_score"] = score_breakdown["python_score"]
    detection["forced_review"] = score_breakdown["forced_review"]
    detection["forced_review_reason"] = score_breakdown["forced_review_reason"]
    evidence_context["deterministic_scoring"] = score_breakdown
    record_pre_ai_threat_intel_usage(conn, detection_id, alert_id, evidence_context)
    try:
        ai_report = ask_ai_model(
            runtime_config,
            alert,
            detection,
            evidence_context=evidence_context,
        )
        ai_report = ensure_ai_report_metadata(runtime_config, alert, ai_report)
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
        )
        ai_report = {
            **prompt_audit,
            "classification": "Human Review Required",
            "confidence": "Low",
            "risk_adjustment": 0,
            "reason": f"AI model unavailable: {exc}",
            "recommended_action": "human_review",
            "summary": "The local AI model was unavailable, so this case requires analyst review.",
            "who": f"{alert.get('src_ip') or 'Unknown source'} and {alert.get('dest_ip') or 'unknown destination'}.",
            "what": alert.get("signature") or "A network sensor finding was recorded.",
            "when": f"Observed at {alert.get('timestamp') or 'an unknown time'}.",
            "where": f"{alert.get('src_ip') or '?'}:{alert.get('src_port') or '?'} to {alert.get('dest_ip') or '?'}:{alert.get('dest_port') or '?'}.",
            "why": "Automated explanation was unavailable; review the deterministic score and sensor evidence.",
            "how": "Python correlated the stored Suricata and Zeek evidence without an AI response.",
            "next_steps": ["Review the original sensor findings and related Zeek context."],
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
    ai_report_id = insert_ai_report(conn, detection_id, ai_report)
    insert_ai_assessment(
        conn,
        detection_id,
        ai_report,
        assessment_type="initial",
        evidence_sources={
            "sensor_findings": [item.get("event_uid") for item in findings],
            "score_breakdown": score_breakdown,
        },
    )
    response = decide(conn, runtime_config, alert, detection, ai_report)
    response["detection_id"] = detection_id
    insert_score_breakdown(
        conn,
        detection_id,
        score_breakdown,
        ai_report_id=ai_report_id,
        assessment_type="initial",
        llm_adjustment_raw=ai_report.get("risk_adjustment", 0),
        llm_adjustment_applied=safe_risk_adjustment(ai_report),
        provisional_score=response["final_score"],
    )
    try:
        ai_report["virustotal_verification"] = verify_dangerous_with_virustotal(
            conn,
            runtime_config,
            alert,
            detection_id,
            alert_id,
            ai_report,
            ai_report_id=ai_report_id,
            stage="initial",
        )
    except ValueError as exc:
        ai_report["virustotal_verification"] = []
        insert_app_event(
            conn,
            "error",
            "threat_intel",
            f"VirusTotal verification could not be completed for detection {detection_id}: {type(exc).__name__}",
        )
    response_id = insert_response(conn, response)
    response["response_id"] = response_id
    upsert_pending_review(conn, response)
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
    mode = "analysis"
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

    start_position = config.get("suricata", {}).get("start_position", "end")
    for record in follow_file(
        eve_path,
        conn=conn,
        start_position=start_position,
    ):
        alert = normalize_suricata_event(record.event)
        if not alert:
            record.acknowledge()
            continue

        alert_id = insert_alert(conn, alert)
        if alert.get("_duplicate") and sensor_finding_detection_id(conn, "suricata", alert_id):
            record.acknowledge()
            continue
        alert["alert_id"] = alert_id
        alert["detection_type"] = detection_type_from_alert(alert)
        match, method, confidence = find_correlated_detection(
            conn,
            alert,
            "suricata",
            tolerance_seconds=int(config.get("correlation", {}).get("sensor_time_tolerance_seconds", 10)),
            same_sensor_window_seconds=int(config.get("correlation", {}).get("same_sensor_window_seconds", 300)),
            strengths=config.get("correlation", {}).get("strengths", {}),
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
        record.acknowledge()


def run_dashboard(config_path, host, port):
    if host == "0.0.0.0":
        print(
            "[!] Dashboard is exposed on every interface and has no built-in authentication. "
            "Restrict access to a trusted management network.",
            flush=True,
        )
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
        message = "Zeek ingestion is required and cannot be disabled. Set zeek.enabled to true."
        insert_app_event(conn, "error", "zeek", message)
        conn.close()
        raise RuntimeError(message)
    if not status.get("installed"):
        message = "Zeek ingestion is required, but zeek/zeekctl was not found. Run bootstrap to install Zeek."
        insert_app_event(conn, "error", "zeek", message, status)
        conn.close()
        raise RuntimeError(message)
    if not status.get("running"):
        message = "Zeek ingestion is required, but the Zeek sensor is not running."
        insert_app_event(conn, "error", "zeek", message, status)
        conn.close()
        raise RuntimeError(message)
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
        alert, detection = zeek_detection(
            event,
            single_sensor_strength=runtime_config.get("correlation", {})
            .get("strengths", {})
            .get("single_sensor", 0.5),
        )
        event["detection_type"] = detection.get("detection_type")
        match, method, confidence = find_correlated_detection(
            conn,
            event,
            "zeek",
            tolerance_seconds=int(runtime_config.get("correlation", {}).get("sensor_time_tolerance_seconds", 10)),
            same_sensor_window_seconds=int(runtime_config.get("correlation", {}).get("same_sensor_window_seconds", 300)),
            strengths=runtime_config.get("correlation", {}).get("strengths", {}),
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
    for name, process, _thread, _recent, _required in processes:
        if process.poll() is None:
            print(f"[+] Stopping {name}", flush=True)
            process.terminate()
    for name, process, _thread, _recent, _required in processes:
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
    restart_suricata=True,
):
    config = load_config(config_path)
    database_path = config.get("database", {}).get("path", "security_vm.db")
    schema_conn = init_db(database_path)
    schema_conn.close()
    print(f"[+] Database schema ready: {database_path}", flush=True)
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
        print("[+] Authenticating once for sensor management", flush=True)
        authorization = subprocess.run(["sudo", "-v"], check=False)
        if authorization.returncode != 0:
            print("[!] Sudo authentication failed; run-all cannot manage the required sensors.", flush=True)
            return
        privileged_prefix = ["sudo", "-n"]

    zeek_enabled = bool(config.get("zeek", {}).get("enabled", True))
    if not zeek_enabled:
        print(
            "[!] Cannot start: Zeek is a required sensor. Set zeek.enabled to true and run bootstrap.",
            flush=True,
        )
        return
    zeek_runtime_status = zeek_status(config)
    if not zeek_runtime_status.get("installed"):
        print(
            "[!] Cannot start: Zeek and zeekctl are required but were not found. Run python -m app.bootstrap.",
            flush=True,
        )
        return

    commands = []
    commands.append((
        "ingest",
        [sys.executable, "-m", "app.main", "ingest", "--config", config_path],
        True,
    ))
    commands.append((
        "zeek-ingest",
        [sys.executable, "-m", "app.main", "zeek-ingest", "--config", config_path],
        True,
    ))
    threat_worker_enabled = any(
        provider_config(config, name).get("enabled") for name in FETCHERS
    )
    if threat_worker_enabled:
        commands.append((
            "threat-intel",
            [sys.executable, "-m", "app.main", "threat-intel", "--config", config_path],
            False,
        ))
    commands.append(
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
            True,
        )
    )

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
    if host == "0.0.0.0":
        print(
            "[!] Dashboard is listening on every interface without built-in authentication. "
            "Use a trusted management network and host firewall rules.",
            flush=True,
        )
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
            suricata_active = run_quiet_command(
                "suricata", privileged_prefix + ["systemctl", "is-active", "suricata"], timeout=10
            )
        if not suricata_active:
            print("[!] Cannot start: Suricata is a required sensor and is not active.", flush=True)
            return

    print("[+] Checking required Zeek sensor", flush=True)
    zeekctl = zeek_runtime_status.get("binaries", {}).get("zeekctl") or "zeekctl"
    if not zeek_runtime_status.get("running"):
        if not run_quiet_command("zeek", privileged_prefix + [zeekctl, "deploy"], timeout=30):
            print("[!] Cannot start: Zeek deploy failed.", flush=True)
            return
    run_quiet_command("zeek", privileged_prefix + [zeekctl, "status"], timeout=10)
    zeek_runtime_status = zeek_status(config)
    if not zeek_runtime_status.get("running"):
        print("[!] Cannot start: Zeek is required but is not running after deploy.", flush=True)
        return

    try:
        for name, command, required in commands:
            recent_lines = deque(maxlen=40)
            process, thread = start_managed_process(name, command, recent_lines)
            processes.append((name, process, thread, recent_lines, required))
            print(f"[+] Started {name}{' (required)' if required else ' (optional)'}", flush=True)

        while not shutting_down:
            for name, process, _thread, recent_lines, required in list(processes):
                return_code = process.poll()
                if return_code is not None:
                    if required:
                        shutting_down = True
                        print(f"[!] Required worker {name} exited with code {return_code}", flush=True)
                        if return_code != 0:
                            print_recent_tail(name, recent_lines)
                        break
                    print(f"[!] Optional worker {name} exited with code {return_code}; core services remain running", flush=True)
                    if return_code != 0:
                        print_recent_tail(name, recent_lines)
                    processes.remove((name, process, _thread, recent_lines, required))
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
        detection = attach_asset_context(detection, asset_context_for_alert(conn, alert))
        evidence_context = build_ai_evidence_context(
            conn,
            config,
            alert,
            detection,
            detection_id=row["detection_id"],
        )
        findings = sensor_findings_for_detection(conn, row["detection_id"])
        breakdown = deterministic_score(alert, detection, findings, evidence_context)
        detection["python_initial_score"] = breakdown["python_score"]
        detection["forced_review"] = breakdown["forced_review"]
        detection["forced_review_reason"] = breakdown["forced_review_reason"]
        evidence_context["deterministic_scoring"] = breakdown
        update_detection_python_score(conn, row["detection_id"], breakdown["python_score"])
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
            )
            report = ensure_ai_report_metadata(config, alert, report)
            report_id = insert_ai_report(conn, row["detection_id"], report)
            insert_ai_assessment(
                conn,
                row["detection_id"],
                report,
                assessment_type="backfill",
                evidence_sources={"score_breakdown": breakdown},
            )
            insert_score_breakdown(
                conn,
                row["detection_id"],
                breakdown,
                ai_report_id=report_id,
                assessment_type="backfill",
                llm_adjustment_raw=report.get("risk_adjustment", 0),
                llm_adjustment_applied=safe_risk_adjustment(report),
            )
            try:
                report["virustotal_verification"] = verify_dangerous_with_virustotal(
                    conn,
                    config,
                    alert,
                    row["detection_id"],
                    row.get("alert_id"),
                    report,
                    ai_report_id=report_id,
                    stage="backfill",
                )
            except ValueError as exc:
                report["virustotal_verification"] = []
                insert_app_event(
                    conn,
                    "error",
                    "threat_intel",
                    f"VirusTotal post-AI verification failed during backfill for detection {row['detection_id']}: {exc}",
                )
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
            )
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

    run_all_parser = sub.add_parser("run-all", help="Start required sensors, ingestion, enrichment, and dashboard")
    run_all_parser.add_argument("--config", default="config.yaml")
    run_all_parser.add_argument("--host", default="127.0.0.1")
    run_all_parser.add_argument("--port", default=8000, type=int)
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

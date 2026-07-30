"""Command-line entry point and orchestration for the Security VM pipeline.

Suricata and Zeek readers persist and correlate sensor evidence without waiting
for network model I/O. A separate required AI worker gathers bounded evidence,
requests an explanation, stores the complete audit, applies Python response
policy, and optionally performs post-classification VirusTotal verification.
"""

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
from datetime import datetime, timezone

import requests
import uvicorn

from app.ai_activity import ai_activity_callback
from app.config import load_config
from app.correlator import Correlator
from app.dashboard import create_app
from app.database import (
    ai_worker_paused,
    connect,
    detection_by_id,
    detections_without_ai_reports,
    find_correlated_detection,
    fuse_detection,
    init_db,
    interrupt_active_ai_requests,
    insert_alert,
    insert_app_event,
    insert_detection,
    insert_ai_assessment,
    insert_ai_report,
    insert_response,
    insert_sensor_finding,
    ip_enrichment_profile,
    latest_threat_intel_for_ip,
    record_runtime_components,
    record_threat_intel_usage,
    sensor_findings_for_detection,
    sensor_finding_detection_id,
    threat_intel_matches,
    upsert_ai_run_audit,
    upsert_pending_review,
    zeek_context_for_detection,
    zeek_flow_for_uid,
)
from app.decision_engine import decide
from app.normalizer import detection_type_from_alert, normalize_suricata_event
from app.ai_client import (
    AIModelRequestCancelled,
    ask_ai_model,
    build_prompt_audit,
    check_ai_model,
    model_metadata,
    model_run_id,
)
from app.ai_comparison import run_experiment_worker
from app.suricata_reader import follow_file, permission_help
from app.sensor_fusion import suricata_finding, zeek_detection, zeek_finding
from app.threat_intel import (
    FETCHERS,
    PRE_AI_PROVIDERS,
    PROVIDERS,
    ai_provider_status,
    provider_config,
    provider_evidence_for_indicator,
    zeek_context_threat_intel,
)
from app.threat_intel_worker import run_threat_intel_worker
from app.zeek_ingest import run_zeek_ingest_loop
from app.zeek_inventory import zeek_status
from app.zeek_normalizer import compact_zeek_context_events
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
    """Build bounded pre-AI reputation evidence for one IP address.

    Only enabled bulk/cached providers are considered. Provider-specific status
    is included so the model can distinguish no match from a disabled source.
    """
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
    """Extract domains, URLs, and hashes from one stored Suricata EVE record."""
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
    """Match non-IP observables against enabled local threat-intelligence data."""
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
    """Record exactly which threat-intelligence matches entered the AI package."""
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
    for observable in (threat_intel.get("zeek_observables") or {}).get("items", []):
        for match in observable.get("matches") or []:
            record_threat_intel_usage(
                conn,
                detection_id,
                alert_id,
                observable.get("indicator"),
                observable.get("indicator_type") or match.get("indicator_type") or "unknown",
                match.get("source") or "unknown",
                "pre_ai_prompt",
                {
                    **match,
                    "zeek_log_types": observable.get("log_types") or [],
                    "associated_ips": observable.get("associated_ips") or [],
                    "provenance": observable.get("provenance") or [],
                },
            )


def build_ai_evidence_context(conn, config, alert, detection=None, detection_id=None):
    """Assemble the selected evidence that will later be embedded in the prompt.

    This function joins normalized findings, bounded Zeek context, recurrence,
    and pre-AI threat intelligence. Raw sensor rows stay in SQLite and are
    represented here by normalized fields, IDs, hashes, and provenance.
    """
    # ``sensor_findings`` is the common Suricata/Zeek view for the case. The
    # original records remain linked through source_table and sensor_event_id.
    findings = sensor_findings_for_detection(conn, detection_id) if detection_id else []
    findings = [
        {
            "sensor": item.get("sensor"),
            "sensor_event_id": item.get("sensor_event_id"),
            "source_table": item.get("source_table"),
            "event_uid": item.get("event_uid"),
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
            "raw_record_sha256": item.get("raw_record_sha256"),
            "raw_record_bytes": item.get("raw_record_bytes"),
            "field_provenance": item.get("field_provenance"),
        }
        for item in findings
    ]
    correlation_config = config.get("correlation", {})
    # The database may find many related Zeek rows. The normal context query can
    # inspect up to the configured limit, while only the eight most relevant
    # normalized rows are included in the AI package.
    zeek_context = zeek_context_for_detection(
        conn,
        detection_id,
        seconds=int(correlation_config.get("zeek_context_window_seconds", 120)),
        limit=int(correlation_config.get("zeek_context_limit", 100)),
    ) if detection_id else {"items": [], "summary": {}}
    # Domains, certificates, hashes, and IPs extracted from those selected Zeek
    # records are matched against the same enabled pre-AI providers.
    zeek_observables = zeek_context_threat_intel(
        conn,
        config,
        zeek_context.get("items") or [],
        limit=8,
        provenance_limit=1,
    )
    zeek_items = zeek_context.get("items") or []
    zeek_context = {
        "window_start": zeek_context.get("window_start"),
        "window_end": zeek_context.get("window_end"),
        "summary": zeek_context.get("summary") or {},
        "selection": {
            "source": "zeek_events",
            "available_count": len(zeek_items),
            "included_count": min(len(zeek_items), 8),
            "limit": 8,
            "policy": "nearest flow, UID, endpoint, and repeated-source context within the configured case window",
        },
        "items": compact_zeek_context_events(zeek_items, limit=8),
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
            "zeek_observables": zeek_observables,
        },
    }


def ensure_ai_report_metadata(config, alert, report):
    """Backfill model/run identity when a compatibility response omitted it."""
    metadata = model_metadata(config)
    for key, value in metadata.items():
        if not report.get(key):
            report[key] = value
    if not report.get("model_run_id"):
        report["model_run_id"] = model_run_id(metadata, alert)
    return report


def assess_detection(conn, config_path, alert, detection, alert_id, detection_id):
    """Run the complete initial assessment for one correlated detection.

    Processing order is intentional:

    1. Reload runtime model settings and gather bounded evidence.
    2. Record pre-AI threat-intelligence usage.
    3. Ask the model, retaining a failed-request audit when unavailable.
    4. Store the report and exact request audit before applying response policy.
    5. Let Python choose the final qualitative action.
    6. Use VirusTotal only as post-AI verification when policy permits.
    """
    runtime_config = load_config(config_path)
    evidence_context = build_ai_evidence_context(
        conn,
        runtime_config,
        alert,
        detection,
        detection_id=detection_id,
    )
    findings = sensor_findings_for_detection(conn, detection_id)
    record_pre_ai_threat_intel_usage(conn, detection_id, alert_id, evidence_context)
    _activity_uid, progress = ai_activity_callback(
        conn,
        runtime_config,
        "initial",
        case_uid=detection.get("case_uid"),
        detection_id=detection_id,
    )
    # Model failure is converted to Analyst Review Required; sensor evidence is
    # never discarded simply because the explanatory service is unavailable.
    try:
        ai_report = ask_ai_model(
            runtime_config,
            alert,
            detection,
            evidence_context=evidence_context,
            progress_callback=progress,
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
    except AIModelRequestCancelled:
        insert_app_event(
            conn,
            "warning",
            "ai_model",
            f"AI analysis cancelled for detection {detection_id}",
            {"detection_id": detection_id, "case_uid": detection.get("case_uid")},
        )
        return None
    except requests.RequestException as exc:
        prompt_audit = getattr(exc, "audit", None)
        if not prompt_audit:
            _, prompt_audit = build_prompt_audit(
                runtime_config,
                alert,
                detection,
                evidence_context=evidence_context,
            )
        ai_report = {
            **prompt_audit,
            "classification": "Analyst Review Required",
            "confidence": "Low",
            "reason": f"AI model unavailable: {exc}",
            "recommended_action": "human_review",
            "summary": "The local AI model was unavailable, so this case requires analyst review.",
            "who": f"{alert.get('src_ip') or 'Unknown source'} and {alert.get('dest_ip') or 'unknown destination'}.",
            "what": alert.get("signature") or "A network sensor finding was recorded.",
            "when": f"Observed at {alert.get('timestamp') or 'an unknown time'}.",
            "where": f"{alert.get('src_ip') or '?'}:{alert.get('src_port') or '?'} to {alert.get('dest_ip') or '?'}:{alert.get('dest_port') or '?'}.",
            "why": "Automated explanation was unavailable; review the stored sensor and threat-intelligence evidence.",
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
    # Store the human-readable report and the authoritative request audit as
    # separate records. The model's evidence acknowledgement is explanatory;
    # Python's captured prompt, hashes, and source map are delivery proof.
    ai_report_id = insert_ai_report(conn, detection_id, ai_report)
    upsert_ai_run_audit(
        conn,
        detection_id,
        ai_report,
        ai_report_id=ai_report_id,
        assessment_type="initial",
    )
    insert_ai_assessment(
        conn,
        detection_id,
        ai_report,
        assessment_type="initial",
        evidence_sources={
            "sensor_findings": [item.get("event_uid") for item in findings],
        },
    )
    # Python retains final control and can force review for disputed sensors.
    response = decide(conn, runtime_config, alert, detection, ai_report)
    response["detection_id"] = detection_id
    try:
        # VirusTotal is deliberately after classification and cannot add or
        # subtract points because this workflow has no operational score.
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
        f"{response['final_classification']} action={response['final_action']}",
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
        f"action={response['final_action']}"
    )
    return response


def run_ingest(config_path):
    """Continuously persist Suricata alerts without waiting for AI analysis."""
    config = load_config(config_path)
    conn = init_db(config.get("database", {}).get("path", "security_vm.db"))
    correlator = Correlator(config)
    eve_path = config.get("suricata", {}).get("eve_json_path", "/var/log/suricata/eve.json")
    mode = "analysis"
    print(f"[+] Security VM ingest starting in {mode} mode")
    insert_app_event(conn, "info", "ingest", f"Security VM ingest starting in {mode} mode")

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
        linked_detection_id = sensor_finding_detection_id(
            conn, "suricata", alert_id
        )
        if alert.get("_duplicate") and linked_detection_id:
            if detection_by_id(conn, linked_detection_id):
                record.acknowledge()
                continue
            conn.execute(
                """
                DELETE FROM sensor_findings
                WHERE detection_id = ? AND sensor = 'suricata'
                  AND sensor_event_id = ?
                """,
                (linked_detection_id, alert_id),
            )
            conn.commit()
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
            if detection is None:
                # A dashboard reset can remove a matched case between lookup
                # and fusion. Recreate the case so this durable alert is not
                # acknowledged with an orphaned sensor-finding link.
                conn.execute(
                    """
                    DELETE FROM sensor_findings
                    WHERE detection_id = ? AND sensor = 'suricata'
                      AND sensor_event_id = ?
                    """,
                    (detection_id, alert_id),
                )
                conn.commit()
                detection = correlator.correlate(alert, alert_id)
                detection_id = insert_detection(conn, detection)
                insert_sensor_finding(
                    conn, detection_id, suricata_finding(alert_id, alert)
                )
        else:
            detection = correlator.correlate(alert, alert_id)
            detection_id = insert_detection(conn, detection)
            insert_sensor_finding(conn, detection_id, suricata_finding(alert_id, alert))
        # The required AI worker picks up this durable, unassessed case. Keeping
        # model I/O out of this loop lets the EVE checkpoint follow Suricata in
        # real time even when a model response takes tens of seconds.
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
        alert, initial_detection = zeek_detection(
            event,
            single_sensor_strength=runtime_config.get("correlation", {})
            .get("strengths", {})
            .get("single_sensor", 0.5),
        )
        event["detection_type"] = initial_detection.get("detection_type")
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
            if detection is None:
                conn.execute(
                    """
                    DELETE FROM sensor_findings
                    WHERE detection_id = ? AND sensor = 'zeek'
                      AND sensor_event_id = ?
                    """,
                    (detection_id, event_id),
                )
                conn.commit()
                detection = initial_detection
                detection_id = insert_detection(conn, detection)
                insert_sensor_finding(
                    conn, detection_id, zeek_finding(event_id, event)
                )
        else:
            detection = initial_detection
            detection_id = insert_detection(conn, detection)
            insert_sensor_finding(conn, detection_id, zeek_finding(event_id, event))
        insert_app_event(
            conn,
            "info",
            "sensor_fusion",
            f"Zeek notice entered detection pipeline as {detection.get('sensor_state')}",
            {"zeek_event_id": event_id, "detection_id": detection_id, "correlation_method": detection.get("correlation_method")},
        )
        # AI analysis is deliberately asynchronous so Zeek log checkpoints are
        # never held behind a remote model request.

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
    interrupted_requests = interrupt_active_ai_requests(schema_conn)
    schema_conn.close()
    print(f"[+] Database schema ready: {database_path}", flush=True)
    if interrupted_requests:
        print(
            f"[+] Reconciled {interrupted_requests} AI request(s) interrupted by the previous shutdown",
            flush=True,
        )
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
    commands.append((
        "ai-worker",
        [sys.executable, "-m", "app.main", "ai-worker", "--config", config_path],
        True,
    ))
    commands.append((
        "experiment-worker",
        [sys.executable, "-m", "app.main", "experiment-worker", "--config", config_path],
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
    launcher_conn = None
    component_started_at = {}

    def publish_runtime_components(force_status=None):
        snapshot = []
        for name, process, _thread, _recent_lines, required in processes:
            return_code = process.poll()
            snapshot.append(
                {
                    "component": name,
                    "status": force_status or (
                        "running" if return_code is None else "exited"
                    ),
                    "pid": process.pid,
                    "required": required,
                    "exit_code": return_code,
                    "started_at": component_started_at.get(name),
                }
            )
        if snapshot and launcher_conn is not None:
            record_runtime_components(launcher_conn, snapshot)

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
    if not os.environ.get("SECURITY_VM_ADMIN_PASSWORD"):
        print(
            "[!] Admin is disabled because SECURITY_VM_ADMIN_PASSWORD is not set. "
            "Set it before launch to use Admin and the Runtime Console.",
            flush=True,
        )
    if host == "0.0.0.0":
        print(
            "[!] The main dashboard is listening on every interface without built-in "
            "authentication. Admin routes use HTTP Basic auth when configured. "
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

    launcher_conn = connect(database_path)
    try:
        for name, command, required in commands:
            recent_lines = deque(maxlen=40)
            process, thread = start_managed_process(name, command, recent_lines)
            processes.append((name, process, thread, recent_lines, required))
            component_started_at[name] = datetime.now(timezone.utc).isoformat()
            publish_runtime_components()
            print(f"[+] Started {name}{' (required)' if required else ' (optional)'}", flush=True)

        last_heartbeat = 0.0
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
            if time.monotonic() - last_heartbeat >= 2:
                publish_runtime_components()
                last_heartbeat = time.monotonic()
            if shutting_down:
                break
            time.sleep(1)
    finally:
        try:
            publish_runtime_components(force_status="stopped")
        finally:
            if launcher_conn is not None:
                launcher_conn.close()
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
            "status": row.get("status"),
        }
        evidence_context = build_ai_evidence_context(
            conn,
            config,
            alert,
            detection,
            detection_id=row["detection_id"],
        )
        findings = sensor_findings_for_detection(conn, row["detection_id"])
        record_pre_ai_threat_intel_usage(
            conn,
            row["detection_id"],
            row.get("alert_id"),
            evidence_context,
        )
        _activity_uid, progress = ai_activity_callback(
            conn,
            config,
            "backfill",
            case_uid=row.get("case_uid"),
            detection_id=row["detection_id"],
        )

        try:
            report = ask_ai_model(
                config,
                alert,
                detection,
                evidence_context=evidence_context,
                progress_callback=progress,
            )
            report = ensure_ai_report_metadata(config, alert, report)
            report_id = insert_ai_report(conn, row["detection_id"], report)
            upsert_ai_run_audit(
                conn,
                row["detection_id"],
                report,
                ai_report_id=report_id,
                assessment_type="backfill",
            )
            insert_ai_assessment(
                conn,
                row["detection_id"],
                report,
                assessment_type="backfill",
                evidence_sources={
                    "sensor_findings": [item.get("event_uid") for item in findings],
                },
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


def assessment_inputs_from_row(conn, row):
    """Rebuild the canonical alert and detection inputs for a queued case."""
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
        "status": row.get("status"),
        "case_uid": row.get("case_uid"),
    }
    return alert, detection


def run_ai_worker(config_path, poll_seconds=1.0, correlation_delay_seconds=5):
    """Continuously assess persisted cases without blocking either sensor."""
    config = load_config(config_path)
    conn = init_db(config.get("database", {}).get("path", "security_vm.db"))
    print("[+] AI assessment worker starting")
    insert_app_event(
        conn,
        "info",
        "ai_model",
        "AI assessment worker starting",
        {"correlation_delay_seconds": correlation_delay_seconds},
    )
    try:
        while True:
            if ai_worker_paused(conn):
                time.sleep(max(0.1, poll_seconds))
                continue
            rows = detections_without_ai_reports(
                conn,
                limit=1,
                minimum_age_seconds=correlation_delay_seconds,
            )
            if not rows:
                time.sleep(max(0.1, poll_seconds))
                continue
            row = rows[0]
            alert, detection = assessment_inputs_from_row(conn, row)
            assess_detection(
                conn,
                config_path,
                alert,
                detection,
                row.get("alert_id"),
                row["detection_id"],
            )
    finally:
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
    ai_worker = sub.add_parser("ai-worker", help="Assess queued cases without blocking sensor ingestion")
    ai_worker.add_argument("--config", default="config.yaml")
    experiment_worker = sub.add_parser(
        "experiment-worker",
        help="Run queued baseline comparisons and controlled LLM experiments",
    )
    experiment_worker.add_argument("--config", default="config.yaml")

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
    elif args.command == "ai-worker":
        run_ai_worker(args.config)
    elif args.command == "experiment-worker":
        run_experiment_worker(args.config)
    elif args.command == "zeek-ingest":
        run_zeek_ingest(args.config)
    elif args.command == "zeek-status":
        run_zeek_status(args.config)
    elif args.command == "threat-intel":
        run_threat_intel(args.config)


if __name__ == "__main__":
    main()

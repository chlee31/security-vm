import json

from app.ai_client import ask_ai_model
from app.database import (
    asset_context_for_alert,
    case_workspace,
    insert_ai_assessment,
    insert_ai_report,
    insert_app_event,
    insert_response,
    insert_score_breakdown,
    latest_threat_intel_for_ip,
    sensor_findings_for_detection,
    threat_intel_matches,
    update_detection_python_score,
    upsert_pending_review,
)
from app.decision_engine import decide, safe_risk_adjustment
from app.risk_score import deterministic_score
from app.threat_intel import (
    PRE_AI_PROVIDERS,
    ai_provider_status,
    provider_config,
    provider_evidence_for_indicator,
)
from app.virustotal import verify_dangerous


def _active_sources(config):
    return {
        source
        for source in PRE_AI_PROVIDERS
        if provider_config(config, source).get("enabled")
    }


def _ip_intel(conn, config, ip_address):
    if not ip_address:
        return None
    active = _active_sources(config)
    return {
        "indicator": ip_address,
        "indicator_type": "ip",
        "matches": [
            item
            for item in threat_intel_matches(conn, ip_address, "ip")
            if item.get("source") in active
        ],
        "legacy_otx": latest_threat_intel_for_ip(conn, ip_address, "otx")
        if "otx" in active
        else None,
        "providers": provider_evidence_for_indicator(conn, config, ip_address),
    }


def _stored_observable_intel(conn, config, workspace, active_sources):
    items = []
    for usage in workspace.get("threat_intel_usage") or []:
        if usage.get("source") == "virustotal" or usage.get("source") not in active_sources:
            continue
        try:
            details = json.loads(usage.get("details_json") or "{}")
        except (TypeError, ValueError):
            details = {}
        items.append(
            {
                "indicator": usage.get("indicator"),
                "indicator_type": usage.get("indicator_type"),
                "matches": [{**details, "source": usage.get("source")}],
                "providers": provider_evidence_for_indicator(
                    conn,
                    config,
                    usage.get("indicator"),
                    usage.get("indicator_type") or "unknown",
                ),
            }
        )
    return items


def _primary_alert(workspace):
    alerts = workspace.get("suricata_alerts") or []
    if alerts:
        return dict(alerts[0])
    findings = workspace.get("zeek_findings") or []
    if findings:
        item = findings[0]
        return {
            "timestamp": item.get("timestamp"),
            "src_ip": item.get("source_ip"),
            "dest_ip": item.get("destination_ip"),
            "src_port": item.get("source_port"),
            "dest_port": item.get("destination_port"),
            "protocol": item.get("protocol"),
            "signature": item.get("event_name") or "Zeek Notice",
            "category": item.get("message") or "Zeek policy notice",
            "priority": 3,
            "raw_json": item.get("raw_json"),
        }
    return {
        "timestamp": workspace.get("first_seen"),
        "src_ip": workspace.get("src_ip"),
        "dest_ip": workspace.get("dest_ip"),
        "src_port": workspace.get("src_port"),
        "dest_port": workspace.get("dest_port"),
        "protocol": workspace.get("protocol"),
        "signature": workspace.get("signature") or "Unified sensor detection",
        "category": workspace.get("category") or "Network detection",
        "priority": workspace.get("priority") or 3,
    }


def build_reassessment_evidence(conn, config, workspace, alert, detection, assessment_type="reassessment"):
    zeek_context = workspace.get("zeek_context") or {"items": []}
    active_sources = _active_sources(config)
    return {
        "case_uid": workspace.get("case_uid"),
        "assessment_type": assessment_type,
        "sensor_fusion": {
            "sensor_state": detection.get("sensor_state"),
            "agreement_state": detection.get("agreement_state"),
            "correlation_method": detection.get("correlation_method"),
            "correlation_confidence": detection.get("correlation_confidence"),
            "community_id": detection.get("community_id"),
            "findings": workspace.get("sensor_findings") or [],
        },
        "zeek_context": {
            "window_start": zeek_context.get("window_start"),
            "window_end": zeek_context.get("window_end"),
            "items": (zeek_context.get("items") or [])[:50],
        },
        "threat_intel": {
            "policy": "Cached and bulk providers inform the deterministic score. VirusTotal remains separate verification evidence.",
            "provider_status": ai_provider_status(config, conn),
            "src_ip": _ip_intel(conn, config, alert.get("src_ip")),
            "dest_ip": _ip_intel(conn, config, alert.get("dest_ip")),
            "alert_observables": _stored_observable_intel(conn, config, workspace, active_sources),
        },
        "existing_virustotal_verification": workspace.get("virustotal_verifications") or [],
        "previous_assessments": [] if assessment_type in {"blind_comparison", "model_comparison"} else [
            {
                "assessment_type": item.get("assessment_type"),
                "model_name": item.get("model_name"),
                "classification": item.get("classification"),
                "confidence": item.get("confidence"),
                "risk_adjustment": item.get("risk_adjustment"),
                "reason": item.get("reason"),
                "created_at": item.get("created_at"),
            }
            for item in (workspace.get("ai_assessments") or [])
        ],
        "analyst_feedback": {
            "status": workspace.get("review_status"),
            "action": workspace.get("analyst_action"),
            "notes": workspace.get("analyst_notes"),
        },
        "forensic_pcap_policy": "PCAP remains local and is not sent during reassessment.",
    }


def prepare_case_context(conn, config, case_uid, assessment_type="reassessment"):
    workspace = case_workspace(conn, case_uid)
    if not workspace:
        raise ValueError("Case not found")
    detection_id = workspace["detection_id"]
    alert = _primary_alert(workspace)
    detection = {
        key: value
        for key, value in workspace.items()
        if key
        in {
            "case_uid",
            "first_seen",
            "last_seen",
            "src_ip",
            "dest_ip",
            "src_port",
            "dest_port",
            "protocol",
            "community_id",
            "sensor_state",
            "agreement_state",
            "correlation_method",
            "correlation_confidence",
            "detection_type",
            "alert_count",
            "unique_dest_ports",
            "unique_dest_hosts",
            "time_window_seconds",
            "mitre_id",
            "mitre_name",
            "python_initial_score",
            "status",
        }
    }
    detection["asset_context"] = asset_context_for_alert(conn, alert)
    findings = sensor_findings_for_detection(conn, detection_id)
    evidence = build_reassessment_evidence(
        conn,
        config,
        workspace,
        alert,
        detection,
        assessment_type=assessment_type,
    )
    breakdown = deterministic_score(alert, detection, findings, evidence)
    detection["python_initial_score"] = breakdown["python_score"]
    detection["forced_review"] = breakdown["forced_review"]
    detection["forced_review_reason"] = breakdown["forced_review_reason"]
    evidence["deterministic_scoring"] = breakdown
    return workspace, alert, detection, evidence, breakdown, findings


def reassess_case(conn, config, case_uid):
    workspace, alert, detection, evidence, breakdown, findings = prepare_case_context(
        conn, config, case_uid
    )
    detection_id = workspace["detection_id"]
    update_detection_python_score(conn, detection_id, breakdown["python_score"])

    report = ask_ai_model(config, alert, detection, evidence_context=evidence)
    report_id = insert_ai_report(conn, detection_id, report)
    assessment_id = insert_ai_assessment(
        conn,
        detection_id,
        report,
        assessment_type="reassessment",
        evidence_sources={
            "case_uid": case_uid,
            "sensor_event_uids": [item.get("event_uid") for item in findings],
            "virustotal_verification_ids": [
                item.get("id") for item in workspace.get("virustotal_verifications") or []
            ],
            "raw_pcap_sent": False,
        },
    )
    response = decide(conn, config, alert, detection, report)
    response["detection_id"] = detection_id
    response_id = insert_response(conn, response)
    upsert_pending_review(conn, response)
    insert_score_breakdown(
        conn,
        detection_id,
        breakdown,
        ai_report_id=report_id,
        assessment_type="reassessment",
        llm_adjustment_raw=report.get("risk_adjustment", 0),
        llm_adjustment_applied=safe_risk_adjustment(report),
        provisional_score=response["final_score"],
    )

    verification = verify_dangerous(
        conn,
        config,
        alert,
        detection_id,
        workspace.get("alert_id"),
        report,
        ai_report_id=report_id,
        stage="reassessment",
    )
    insert_app_event(
        conn,
        "info",
        "reassessment",
        f"Case {case_uid} reassessed as {response['final_classification']}",
        {
            "case_uid": case_uid,
            "assessment_id": assessment_id,
            "response_id": response_id,
            "raw_pcap_sent": False,
        },
    )
    return {
        "case_uid": case_uid,
        "assessment_id": assessment_id,
        "response_id": response_id,
        "score_breakdown": breakdown,
        "response": response,
        "virustotal_verification": verification,
    }


def refresh_case_virustotal(conn, config, case_uid):
    workspace = case_workspace(conn, case_uid)
    if not workspace:
        raise ValueError("Case not found")
    alert = _primary_alert(workspace)
    results = verify_dangerous(
        conn,
        config,
        alert,
        workspace["detection_id"],
        workspace.get("alert_id"),
        {"classification": "Dangerous"},
        stage="manual",
        force_refresh=True,
    )
    insert_app_event(
        conn,
        "info",
        "threat_intel",
        f"Analyst manually refreshed VirusTotal for case {case_uid}",
        {"case_uid": case_uid, "result_count": len(results)},
    )
    return results

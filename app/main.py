import argparse
import subprocess
from datetime import timedelta
from pathlib import Path

import requests
import uvicorn

from app.config import load_config
from app.correlator import Correlator
from app.dashboard import create_app
from app.database import (
    asset_context_for_alert,
    detections_without_ollama_reports,
    init_db,
    insert_alert,
    insert_app_event,
    insert_detection,
    insert_incident_evidence,
    insert_ollama_report,
    insert_response,
    ip_enrichment_profile,
    latest_threat_intel_for_ip,
    upsert_pending_review,
)
from app.decision_engine import decide
from app.firewall import temporary_block_firewalld
from app.normalizer import normalize_suricata_event
from app.ollama_client import ask_ollama, build_prompt_audit, check_ollama, model_metadata, model_run_id
from app.pcap_inventory import list_pcap_files, parse_event_time
from app.risk_score import cap_score
from app.suricata_reader import follow_file
from app.tshark_summary import summarize_pcap


def compact_threat_intel(conn, ip_address):
    if not ip_address:
        return None
    return {
        "local_profile": ip_enrichment_profile(ip_address),
        "otx": latest_threat_intel_for_ip(conn, ip_address, "otx"),
    }


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
    max_ai_files = max(0, int(pcap_config.get("max_ai_files", 3)))
    summary_limit = max(1, int(pcap_config.get("summary_packet_limit", 120)))
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
        max_ai_files = int(config.get("pcap", {}).get("max_ai_files", 3))
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
        "note": "Raw PCAP bytes are not sent to the AI model; related capture files are listed for analyst follow-up.",
    }


def build_ai_evidence_context(conn, config, alert, detection=None, pcap_package=None):
    return {
        "threat_intel": {
            "src_ip": compact_threat_intel(conn, alert.get("src_ip")),
            "dest_ip": compact_threat_intel(conn, alert.get("dest_ip")),
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


def run_ingest(config_path):
    config = load_config(config_path)
    conn = init_db(config.get("database", {}).get("path", "security_vm.db"))
    correlator = Correlator(config)
    eve_path = config.get("suricata", {}).get("eve_json_path", "/var/log/suricata/eve.json")
    mode = config.get("system", {}).get("mode", "alert_only")
    print(f"[+] Security VM ingest starting in {mode} mode")
    insert_app_event(conn, "info", "ingest", f"Security VM ingest starting in {mode} mode")

    try:
        status = check_ollama(config)
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
        detection = correlator.correlate(alert, alert_id)
        detection = apply_asset_context(detection, asset_context_for_alert(conn, alert))
        detection_id = insert_detection(conn, detection)
        runtime_config = load_config(config_path)
        pcap_package = prepare_pcap_evidence(runtime_config, alert, detection, alert_id, detection_id)
        evidence_context = build_ai_evidence_context(conn, runtime_config, alert, detection, pcap_package)
        ai_sent = False

        try:
            ollama_report = ask_ollama(
                runtime_config,
                alert,
                detection,
                evidence_context=evidence_context,
                pcap_summary=pcap_package["prompt_summary"],
            )
            ollama_report = ensure_ai_report_metadata(runtime_config, alert, ollama_report)
            ai_sent = True
            insert_app_event(
                conn,
                "info",
                "ai_model",
                f"AI model classified alert as {ollama_report.get('classification', 'Unknown')}",
                {
                    "alert_id": alert_id,
                    "detection_id": detection_id,
                    "elapsed_ms": ollama_report.get("elapsed_ms"),
                    "confidence": ollama_report.get("confidence"),
                    "model_identity": ollama_report.get("model_identity"),
                    "model_run_id": ollama_report.get("model_run_id"),
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
            ollama_report = {
                **prompt_audit,
                "classification": "Human Review Required",
                "confidence": "Low",
                "risk_adjustment": 0,
                "reason": f"AI model unavailable: {exc}",
                "recommended_action": "human_review",
                "raw_response": "",
                "elapsed_ms": int(runtime_config.get("ollama", {}).get("timeout_seconds", 90)) * 1000,
            }
            insert_app_event(
                conn,
                "error",
                "ai_model",
                f"AI model unavailable while reviewing alert {alert_id}: {exc}",
                {
                    "alert_id": alert_id,
                    "detection_id": detection_id,
                    "model_identity": ollama_report.get("model_identity"),
                    "model_run_id": ollama_report.get("model_run_id"),
                },
            )
        store_pcap_evidence(conn, pcap_package, ollama_report, ai_sent=ai_sent)
        insert_ollama_report(conn, detection_id, ollama_report)

        response = decide(conn, runtime_config, alert, detection, ollama_report)
        response["detection_id"] = detection_id

        if response["final_action"] == "temporary_block":
            timeout = runtime_config.get("firewall", {}).get("block_timeout_seconds", 3600)
            status, elapsed_ms = temporary_block_firewalld(response["target_ip"], timeout)
            response["response_status"] = status
            response["response_time_ms"] = elapsed_ms

        insert_response(conn, response)
        upsert_pending_review(conn, response)
        insert_app_event(
            conn,
            "info",
            "decision",
            f"{response['final_classification']} action={response['final_action']} score={response['final_score']}",
            {"alert_id": alert_id, "detection_id": detection_id, "target_ip": response.get("target_ip")},
        )
        print(
            f"[{response['final_classification']}] {alert['src_ip']} -> {alert['dest_ip']} "
            f"{alert['signature']} score={response['final_score']} action={response['final_action']}"
        )


def run_dashboard(config_path, host, port):
    app = create_app(config_path)
    uvicorn.run(app, host=host, port=port)


def run_ollama_backfill(config_path, limit):
    config = load_config(config_path)
    conn = init_db(config.get("database", {}).get("path", "security_vm.db"))
    metadata = model_metadata(config)
    rows = detections_without_ollama_reports(
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
        status = check_ollama(config)
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
            "pcap_point": row.get("pcap_point"),
            "raw_json": row.get("raw_json"),
        }
        detection = {
            "first_alert_id": row.get("first_alert_id"),
            "first_seen": row.get("first_seen"),
            "last_seen": row.get("last_seen"),
            "src_ip": row.get("src_ip"),
            "dest_ip": row.get("dest_ip"),
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
        evidence_context = build_ai_evidence_context(conn, config, alert, detection, pcap_package)

        try:
            report = ask_ollama(
                config,
                alert,
                detection,
                evidence_context=evidence_context,
                pcap_summary=pcap_package["prompt_summary"],
            )
            report = ensure_ai_report_metadata(config, alert, report)
            store_pcap_evidence(conn, pcap_package, report, ai_sent=True)
            insert_ollama_report(conn, row["detection_id"], report)
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

    ai_backfill = sub.add_parser("ai-backfill", help="Ask the AI model for opinions on detections without reports")
    ai_backfill.add_argument("--config", default="config.yaml")
    ai_backfill.add_argument("--limit", default=50, type=int)

    ollama_backfill = sub.add_parser("ollama-backfill", help="Legacy alias for ai-backfill")
    ollama_backfill.add_argument("--config", default="config.yaml")
    ollama_backfill.add_argument("--limit", default=50, type=int)

    args = parser.parse_args()
    if args.command == "ingest":
        run_ingest(args.config)
    elif args.command == "dashboard":
        run_dashboard(args.config, args.host, args.port)
    elif args.command in {"ollama-backfill", "ai-backfill"}:
        run_ollama_backfill(args.config, args.limit)


if __name__ == "__main__":
    main()

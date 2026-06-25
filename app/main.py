import argparse

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
    insert_ollama_report,
    insert_response,
    upsert_pending_review,
)
from app.decision_engine import decide
from app.firewall import temporary_block_firewalld
from app.normalizer import normalize_suricata_event
from app.ollama_client import ask_ollama, check_ollama
from app.risk_score import cap_score
from app.suricata_reader import follow_file


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
            "ollama",
            f"Ollama reachable at {status['host']}",
            {"elapsed_ms": status["elapsed_ms"], "models": status["models"]},
        )
    except requests.RequestException as exc:
        insert_app_event(conn, "error", "ollama", f"Ollama unreachable: {exc}")

    for event in follow_file(eve_path):
        alert = normalize_suricata_event(event)
        if not alert:
            continue

        alert_id = insert_alert(conn, alert)
        detection = correlator.correlate(alert, alert_id)
        detection = apply_asset_context(detection, asset_context_for_alert(conn, alert))
        detection_id = insert_detection(conn, detection)

        try:
            ollama_report = ask_ollama(config, alert, detection)
            insert_app_event(
                conn,
                "info",
                "ollama",
                f"Ollama classified alert as {ollama_report.get('classification', 'Unknown')}",
                {
                    "alert_id": alert_id,
                    "detection_id": detection_id,
                    "elapsed_ms": ollama_report.get("elapsed_ms"),
                    "confidence": ollama_report.get("confidence"),
                },
            )
        except requests.RequestException as exc:
            ollama_report = {
                "classification": "Human Review Required",
                "confidence": "Low",
                "risk_adjustment": 0,
                "reason": f"Ollama unavailable: {exc}",
                "recommended_action": "human_review",
                "raw_response": "",
            }
            insert_app_event(
                conn,
                "error",
                "ollama",
                f"Ollama unavailable while reviewing alert {alert_id}: {exc}",
                {"alert_id": alert_id, "detection_id": detection_id},
            )
        insert_ollama_report(conn, detection_id, ollama_report)

        response = decide(conn, config, alert, detection, ollama_report)
        response["detection_id"] = detection_id

        if response["final_action"] == "temporary_block":
            timeout = config.get("firewall", {}).get("block_timeout_seconds", 3600)
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
    rows = detections_without_ollama_reports(conn, limit)
    print(f"[+] Backfilling Ollama opinions for {len(rows)} detections")
    insert_app_event(conn, "info", "ollama", f"Starting Ollama backfill for {len(rows)} detections")

    try:
        status = check_ollama(config)
        insert_app_event(
            conn,
            "info",
            "ollama",
            f"Ollama reachable at {status['host']}",
            {"elapsed_ms": status["elapsed_ms"], "models": status["models"]},
        )
    except requests.RequestException as exc:
        insert_app_event(conn, "error", "ollama", f"Ollama unreachable before backfill: {exc}")
        print(f"[!] Ollama unreachable: {exc}")
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

        try:
            report = ask_ollama(config, alert, detection)
            insert_ollama_report(conn, row["detection_id"], report)
            insert_app_event(
                conn,
                "info",
                "ollama",
                f"Backfilled detection {row['detection_id']} as {report.get('classification', 'Unknown')}",
                {"detection_id": row["detection_id"], "elapsed_ms": report.get("elapsed_ms")},
            )
            print(f"[+] detection {row['detection_id']} -> {report.get('classification', 'Unknown')}")
        except requests.RequestException as exc:
            insert_app_event(
                conn,
                "error",
                "ollama",
                f"Ollama unavailable while backfilling detection {row['detection_id']}: {exc}",
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

    ollama_backfill = sub.add_parser("ollama-backfill", help="Ask Ollama for opinions on detections without reports")
    ollama_backfill.add_argument("--config", default="config.yaml")
    ollama_backfill.add_argument("--limit", default=50, type=int)

    args = parser.parse_args()
    if args.command == "ingest":
        run_ingest(args.config)
    elif args.command == "dashboard":
        run_dashboard(args.config, args.host, args.port)
    elif args.command == "ollama-backfill":
        run_ollama_backfill(args.config, args.limit)


if __name__ == "__main__":
    main()

import argparse
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
    detections_without_ai_reports,
    init_db,
    insert_alert,
    insert_app_event,
    insert_detection,
    insert_firewall_block,
    insert_ai_report,
    insert_response,
    ip_enrichment_profile,
    latest_threat_intel_for_ip,
    upsert_pending_review,
)
from app.decision_engine import decide
from app.firewall import temporary_block_firewalld
from app.normalizer import normalize_suricata_event
from app.ai_client import ask_ai_model, check_ai_model, model_metadata, model_run_id
from app.notifications import notify_dangerous_decision
from app.pcap_inventory import list_pcap_files
from app.risk_score import cap_score
from app.suricata_reader import follow_file


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


def compact_threat_intel(conn, ip_address):
    if not ip_address:
        return None
    return {
        "local_profile": ip_enrichment_profile(ip_address),
        "otx": latest_threat_intel_for_ip(conn, ip_address, "otx"),
    }


def compact_pcap_evidence(config, alert):
    inventory = list_pcap_files(config, alert.get("timestamp"), alert.get("timestamp"))
    related = [file for file in inventory.get("files", []) if file.get("related")]
    return {
        "status": inventory.get("status"),
        "directory": inventory.get("directory"),
        "window_minutes": inventory.get("window_minutes"),
        "related_file_count": len(related),
        "related_files": [
            {
                "name": file.get("name"),
                "label": file.get("label"),
                "size_bytes": file.get("size_bytes"),
                "modified_at": file.get("modified_at"),
            }
            for file in related[:5]
        ],
        "packet_summary": "not_generated",
        "note": "Raw PCAP bytes are not sent to the AI model; related capture files are listed for analyst follow-up.",
    }


def build_ai_evidence_context(conn, config, alert):
    return {
        "threat_intel": {
            "src_ip": compact_threat_intel(conn, alert.get("src_ip")),
            "dest_ip": compact_threat_intel(conn, alert.get("dest_ip")),
        },
        "pcap_evidence": compact_pcap_evidence(config, alert),
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
        detection = correlator.correlate(alert, alert_id)
        detection = apply_asset_context(detection, asset_context_for_alert(conn, alert))
        detection_id = insert_detection(conn, detection)
        runtime_config = load_config(config_path)
        evidence_context = build_ai_evidence_context(conn, runtime_config, alert)

        try:
            ai_report = ask_ai_model(runtime_config, alert, detection, evidence_context=evidence_context)
            ai_report = ensure_ai_report_metadata(runtime_config, alert, ai_report)
            insert_app_event(
                conn,
                "info",
                "ai_model",
                f"AI model classified alert as {ai_report.get('classification', 'Unknown')}",
                {
                    "alert_id": alert_id,
                    "detection_id": detection_id,
                    "elapsed_ms": ai_report.get("elapsed_ms"),
                    "confidence": ai_report.get("confidence"),
                    "model_identity": ai_report.get("model_identity"),
                    "model_run_id": ai_report.get("model_run_id"),
                },
            )
        except requests.RequestException as exc:
            metadata = model_metadata(runtime_config)
            ai_report = {
                **metadata,
                "model_run_id": model_run_id(metadata, alert),
                "classification": "Human Review Required",
                "confidence": "Low",
                "risk_adjustment": 0,
                "reason": f"AI model unavailable: {exc}",
                "recommended_action": "human_review",
                "raw_response": "",
            }
            insert_app_event(
                conn,
                "error",
                "ai_model",
                f"AI model unavailable while reviewing alert {alert_id}: {exc}",
                {
                    "alert_id": alert_id,
                    "detection_id": detection_id,
                    "model_identity": ai_report.get("model_identity"),
                    "model_run_id": ai_report.get("model_run_id"),
                },
            )
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
            {"alert_id": alert_id, "detection_id": detection_id, "target_ip": response.get("target_ip")},
        )
        print(
            f"[{response['final_classification']}] {alert['src_ip']} -> {alert['dest_ip']} "
            f"{alert['signature']} score={response['final_score']} action={response['final_action']}"
        )


def run_dashboard(config_path, host, port):
    app = create_app(config_path)
    uvicorn.run(app, host=host, port=port)


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
    pcap_config = config.get("pcap", {})
    external_interface = external_interface or pcap_config.get("external_interface", "ens33")
    internal_interface = internal_interface or pcap_config.get("internal_interface") or config.get("assets", {}).get(
        "internal_interface", "ens37"
    )
    pcap_dir = pcap_dir or pcap_config.get("rolling_dir", "/var/log/pcap")
    project_root = Path(__file__).resolve().parents[1]
    pcap_script = project_root / "scripts" / "start_pcap_capture.sh"

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print(
            "[!] run-all is not running as root. Ingest and PCAP capture may fail on /var/log paths. "
            "Use: sudo ./venv/bin/python -m app.main run-all --config config.yaml --host 0.0.0.0 --port 8000",
            flush=True,
        )

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
        run_quiet_command("suricata", ["systemctl", "restart", "suricata"])
        run_quiet_command("suricata", ["systemctl", "is-active", "suricata"])

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
        evidence_context = build_ai_evidence_context(conn, config, alert)

        try:
            report = ask_ai_model(config, alert, detection, evidence_context=evidence_context)
            report = ensure_ai_report_metadata(config, alert, report)
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


if __name__ == "__main__":
    main()

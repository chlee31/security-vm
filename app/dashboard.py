from pathlib import Path
import importlib.util
import getpass
import ipaddress
import os
import shutil
import sqlite3
import subprocess
import sys
from typing import Optional
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
import requests
from pydantic import BaseModel

from app.allowlist import add_allowlist_entry, deactivate_allowlist_entry, list_allowlist_entries
from app.config import load_config, save_config
from app.database import (
    asset_summary,
    connect,
    deactivate_asset,
    delete_asset,
    default_asset_score,
    default_asset_types,
    init_db,
    insert_app_event,
    detection_type_detail,
    detection_time_window,
    enrichment_status,
    latest_alerts,
    latest_app_events,
    latest_decision_evidence,
    latest_ollama_reports,
    list_all_assets,
    list_assets,
    list_review_queue,
    public_ips_for_enrichment,
    reset_dashboard_logs,
    submit_analyst_review,
    upsert_threat_intel_lookup,
    upsert_asset,
    update_asset,
)
from app.enrichment import lookup_otx_ip, test_otx_connection
from app.ollama_client import check_ollama
from app.pcap_inventory import list_pcap_files


STATIC_DIR = Path(__file__).resolve().parents[1] / "static"


class AllowlistRequest(BaseModel):
    ip_address: str
    name: str = ""
    duration_hours: int
    reason: str
    added_by: str = "dashboard"


class AnalystReviewRequest(BaseModel):
    action: str
    analyst_name: str = ""
    notes: str = ""
    score: int = None
    classification: str = None
    tuning_label: str = ""


class AssetRequest(BaseModel):
    ip_address: str
    name: str
    device_type: str
    network_interface: str = ""
    asset_score: int = None
    function: str = ""
    notes: str = ""


class AdminAssetRequest(AssetRequest):
    status: str = "active"


class OllamaConfigRequest(BaseModel):
    host: str
    model: str
    timeout_seconds: int = 90


class ResetLogsRequest(BaseModel):
    confirm: str


class ThreatIntelConfigRequest(BaseModel):
    otx_enabled: bool = False
    otx_api_key: str = ""
    cache_ttl_hours: int = 24


class OtxLookupRequest(BaseModel):
    limit: int = 5
    scope: str = "top5"
    detection_type: Optional[str] = None


class OtxStatusRequest(BaseModel):
    otx_api_key: str = ""


ADMIN_SYSTEM_TOOLS = {
    "Python": {"binary": "python3", "package": "python3 python3-venv python3-pip"},
    "Suricata": {"binary": "suricata", "package": "suricata"},
    "Suricata Update": {"binary": "suricata-update", "package": "suricata-update"},
    "SQLite CLI": {"binary": "sqlite3", "package": "sqlite3"},
    "curl": {"binary": "curl", "package": "curl"},
    "dumpcap": {"binary": "dumpcap", "package": "wireshark-common"},
    "tshark": {"binary": "tshark", "package": "tshark"},
    "firewalld": {"binary": "firewall-cmd", "package": "firewalld"},
    "Tailscale": {"binary": "tailscale", "package": "tailscale"},
}

ADMIN_PYTHON_PACKAGES = {
    "FastAPI": {"module": "fastapi", "package": "fastapi", "distribution": "fastapi"},
    "Uvicorn": {"module": "uvicorn", "package": "uvicorn", "distribution": "uvicorn"},
    "PyYAML": {"module": "yaml", "package": "PyYAML", "distribution": "PyYAML"},
    "Requests": {"module": "requests", "package": "requests", "distribution": "requests"},
}

OLLAMA_MODEL_SUGGESTIONS = [
    "llama3.1:8b",
    "llama3.2:latest",
    "deepseek-r1:8b",
    "deepseek-r1:latest",
]


def tool_status():
    tools = []
    current_user = getpass.getuser()
    for name, meta in ADMIN_SYSTEM_TOOLS.items():
        binary = meta["binary"]
        package = meta["package"]
        if name == "Python":
            path = sys.executable
            installed = bool(path)
            executable = True
            version = sys.version.split()[0]
        else:
            path = shutil.which(binary, mode=os.F_OK)
            installed = bool(path)
            executable = bool(path and os.access(path, os.X_OK))
            version = tool_version(path) if executable else ""
        if installed and executable:
            status = "ready"
            notes = "Available on PATH."
        elif installed:
            status = "permission_limited"
            notes = "Installed, but the dashboard user cannot execute it."
            if binary == "dumpcap":
                notes = "Installed, but packet capture needs wireshark group access or sudo. After adding the user, log out and back in or run newgrp wireshark, then restart the dashboard."
        else:
            status = "missing"
            notes = "Not found on PATH."
        tools.append(
            {
                "name": name,
                "binary": binary,
                "installed": installed,
                "executable": executable,
                "status": status,
                "path": path or "",
                "version": version,
                "notes": notes,
                "install_command": f"sudo apt install -y {package}",
                "update_command": f"sudo apt update && sudo apt install --only-upgrade -y {package}",
                "fix_command": f"sudo usermod -aG wireshark {current_user}"
                if binary == "dumpcap" and installed and not executable
                else "",
                "after_fix": "Log out and back in, or run: newgrp wireshark. Then restart the dashboard.",
            }
        )
    return tools


def tool_version(path):
    commands = ([path, "--version"], [path, "-V"], [path, "version"])
    for command in commands:
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=3, check=False)
        except (OSError, subprocess.SubprocessError):
            continue
        text = (result.stdout or result.stderr or "").strip()
        if text:
            return text.splitlines()[0][:140]
    return "installed, version unknown"


def python_package_status():
    packages = []
    for name, meta in ADMIN_PYTHON_PACKAGES.items():
        module_name = meta["module"]
        spec = importlib.util.find_spec(module_name)
        version = ""
        if spec is not None:
            try:
                from importlib import metadata

                version = metadata.version(meta["distribution"])
            except Exception:
                version = "installed, version unknown"
        packages.append(
            {
                "name": name,
                "module": module_name,
                "installed": spec is not None,
                "version": version,
                "source": "requirements.txt",
                "install_command": f"./venv/bin/python -m pip install -U {meta['package']}",
                "update_command": "./venv/bin/python -m pip install -U -r requirements.txt",
            }
        )
    return packages


def validate_ollama_config(payload):
    host = payload.host.strip().rstrip("/")
    model = payload.model.strip()
    parsed = urlparse(host)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(status_code=400, detail="Ollama host must look like http://IP:11434")
    if not model:
        raise HTTPException(status_code=400, detail="Ollama model is required")
    if payload.timeout_seconds < 5 or payload.timeout_seconds > 300:
        raise HTTPException(status_code=400, detail="Timeout must be between 5 and 300 seconds")
    return host, model, payload.timeout_seconds


def create_app(config_path):
    config = load_config(config_path)
    db_path = config.get("database", {}).get("path", "security_vm.db")
    init_db(db_path).close()
    app = FastAPI(title="Security VM Dashboard")
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/")
    def index():
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/detection")
    def detection_workbook():
        return FileResponse(STATIC_DIR / "detection.html")

    @app.get("/outcome")
    def outcome_workbook():
        return FileResponse(STATIC_DIR / "outcome.html")

    @app.get("/admin")
    def admin_controls():
        return FileResponse(STATIC_DIR / "admin.html")

    @app.get("/api/admin/settings")
    def api_admin_settings(limit: int = 500):
        conn = connect(db_path)
        try:
            return {
                "config_path": str(config_path),
                "database_path": db_path,
                "ollama": {
                    "host": config.get("ollama", {}).get("host", ""),
                    "model": config.get("ollama", {}).get("model", ""),
                    "timeout_seconds": config.get("ollama", {}).get("timeout_seconds", 90),
                    "model_suggestions": OLLAMA_MODEL_SUGGESTIONS,
                },
                "network": {
                    "internal_interface": config.get("assets", {}).get("internal_interface", "ens37"),
                    "suricata_eve_json_path": config.get("suricata", {}).get("eve_json_path", ""),
                    "pcap_rolling_dir": config.get("pcap", {}).get("rolling_dir", ""),
                },
                "assets": {
                    "types": default_asset_types(config),
                    "summary": asset_summary(conn),
                    "items": list_all_assets(conn, limit),
                },
                "tools": tool_status(),
                "python_packages": python_package_status(),
            }
        finally:
            conn.close()

    @app.post("/api/admin/ollama")
    def api_admin_ollama(payload: OllamaConfigRequest):
        host, model, timeout_seconds = validate_ollama_config(payload)
        config.setdefault("ollama", {})
        config["ollama"]["host"] = host
        config["ollama"]["model"] = model
        config["ollama"]["timeout_seconds"] = timeout_seconds
        save_config(config, config_path)

        conn = connect(db_path)
        try:
            insert_app_event(
                conn,
                "info",
                "admin",
                f"Updated Ollama settings to {model} at {host}",
                {"host": host, "model": model, "timeout_seconds": timeout_seconds},
            )
        finally:
            conn.close()
        return {"status": "saved", "host": host, "model": model, "timeout_seconds": timeout_seconds}

    @app.put("/api/admin/assets/{asset_id}")
    def api_admin_update_asset(asset_id: int, payload: AdminAssetRequest):
        try:
            ip_address = str(ipaddress.ip_address(payload.ip_address.strip()))
        except ValueError:
            raise HTTPException(status_code=400, detail="Enter a valid IPv4 or IPv6 address")

        name = payload.name.strip()
        if not name:
            raise HTTPException(status_code=400, detail="Asset name is required")

        allowed_types = {item["value"] for item in default_asset_types(config)}
        device_type = payload.device_type.strip()
        if device_type not in allowed_types:
            raise HTTPException(status_code=400, detail="Unsupported device type")

        status = payload.status.strip().lower()
        if status not in {"active", "inactive"}:
            raise HTTPException(status_code=400, detail="Asset status must be active or inactive")

        score = payload.asset_score
        if score is None:
            score = default_asset_score(config, device_type)
        if score < 0 or score > 10:
            raise HTTPException(status_code=400, detail="Asset score must be between 0 and 10")

        conn = connect(db_path)
        try:
            try:
                ok = update_asset(
                    conn,
                    asset_id,
                    {
                        "ip_address": ip_address,
                        "name": name,
                        "device_type": device_type,
                        "network_interface": payload.network_interface.strip()
                        or config.get("assets", {}).get("internal_interface", "ens37"),
                        "asset_score": score,
                        "function": payload.function.strip(),
                        "notes": payload.notes.strip(),
                        "status": status,
                    },
                )
            except sqlite3.IntegrityError:
                raise HTTPException(status_code=400, detail="Another asset already uses that IP address")
            if not ok:
                raise HTTPException(status_code=404, detail="Asset not found")
            insert_app_event(conn, "info", "admin", f"Updated asset {name} ({ip_address})", {"asset_id": asset_id})
            return {"status": "saved", "id": asset_id}
        finally:
            conn.close()

    @app.delete("/api/admin/assets/{asset_id}")
    def api_admin_delete_asset(asset_id: int):
        conn = connect(db_path)
        try:
            if not delete_asset(conn, asset_id):
                raise HTTPException(status_code=404, detail="Asset not found")
            insert_app_event(conn, "warning", "admin", f"Deleted asset {asset_id}")
            return {"status": "deleted"}
        finally:
            conn.close()

    @app.get("/api/alerts")
    def api_alerts(limit: int = 50):
        conn = connect(db_path)
        try:
            return latest_alerts(conn, limit)
        finally:
            conn.close()

    @app.get("/api/ollama-reports")
    def api_ollama_reports(limit: int = 50):
        conn = connect(db_path)
        try:
            return latest_ollama_reports(conn, limit)
        finally:
            conn.close()

    @app.get("/api/detection-detail")
    def api_detection_detail(detection_type: str = None, limit: int = 50):
        conn = connect(db_path)
        try:
            return detection_type_detail(conn, detection_type, limit)
        finally:
            conn.close()

    @app.get("/api/enrichment-status")
    def api_enrichment_status(limit: int = 50):
        conn = connect(db_path)
        try:
            return enrichment_status(conn, config, limit)
        finally:
            conn.close()

    @app.post("/api/threat-intel-config")
    def api_threat_intel_config(payload: ThreatIntelConfigRequest):
        if payload.cache_ttl_hours < 1 or payload.cache_ttl_hours > 168:
            raise HTTPException(status_code=400, detail="Cache TTL must be between 1 and 168 hours")
        config.setdefault("threat_intel", {})
        config["threat_intel"]["cache_ttl_hours"] = payload.cache_ttl_hours
        config["threat_intel"]["otx_enabled"] = payload.otx_enabled
        if payload.otx_api_key.strip():
            config["threat_intel"]["otx_api_key"] = payload.otx_api_key.strip()
        elif not payload.otx_enabled:
            config["threat_intel"]["otx_api_key"] = ""
        save_config(config, config_path)

        conn = connect(db_path)
        try:
            insert_app_event(
                conn,
                "info",
                "enrichment",
                "Updated OTX enrichment settings",
                {
                    "otx_enabled": payload.otx_enabled,
                    "api_key_configured": bool(config["threat_intel"].get("otx_api_key")),
                    "cache_ttl_hours": payload.cache_ttl_hours,
                },
            )
            return {
                "status": "saved",
                "otx_enabled": payload.otx_enabled,
                "api_key_configured": bool(config["threat_intel"].get("otx_api_key")),
            }
        finally:
            conn.close()

    @app.post("/api/otx-lookups")
    def api_otx_lookups(payload: OtxLookupRequest):
        if payload.scope not in {"top5", "top10", "visible"}:
            raise HTTPException(status_code=400, detail="Unsupported OTX lookup scope")
        if payload.scope == "top5":
            lookup_limit = 5
        elif payload.scope == "top10":
            lookup_limit = 10
        else:
            lookup_limit = 50
        if payload.limit:
            lookup_limit = min(lookup_limit, max(1, int(payload.limit)))
        if not config.get("threat_intel", {}).get("otx_enabled") or not config.get("threat_intel", {}).get("otx_api_key"):
            raise HTTPException(status_code=400, detail="Configure and enable OTX first")

        conn = connect(db_path)
        results = []
        try:
            candidates = public_ips_for_enrichment(
                conn,
                lookup_limit,
                detection_type=payload.detection_type if payload.scope == "visible" else None,
            )
            if not candidates:
                insert_app_event(conn, "warning", "enrichment", "No public IPs available for OTX lookup", {"scope": payload.scope})
                return {"status": "done", "results": [], "message": "No public IPs available for this OTX lookup scope"}
            for candidate in candidates:
                ip_address = candidate["ip_address"]
                try:
                    result = lookup_otx_ip(config, ip_address)
                    upsert_threat_intel_lookup(
                        conn,
                        result["indicator"],
                        "otx",
                        result["reputation"],
                        malicious_count=result["malicious_count"],
                        suspicious_count=result["suspicious_count"],
                        lookup_result=result["lookup_result"],
                        raw_response=result["raw_response"],
                    )
                    results.append({"ip_address": ip_address, "status": "ok", "reputation": result["reputation"]})
                except requests.RequestException as exc:
                    insert_app_event(conn, "error", "enrichment", f"OTX lookup failed for {ip_address}: {exc}")
                    results.append({"ip_address": ip_address, "status": "error", "error": str(exc)})
                except Exception as exc:
                    insert_app_event(conn, "error", "enrichment", f"OTX lookup failed for {ip_address}: {exc}")
                    results.append({"ip_address": ip_address, "status": "error", "error": str(exc)})
            insert_app_event(conn, "info", "enrichment", f"Completed OTX lookups for {len(results)} public IPs", results)
            return {"status": "done", "results": results}
        finally:
            conn.close()

    @app.post("/api/otx-status")
    def api_otx_status(payload: OtxStatusRequest):
        api_key = payload.otx_api_key.strip() or config.get("threat_intel", {}).get("otx_api_key", "")
        if not api_key:
            return {"ok": False, "status": "missing_key", "error": "OTX API key is missing"}

        conn = connect(db_path)
        try:
            try:
                status = test_otx_connection(api_key)
                insert_app_event(
                    conn,
                    "info",
                    "enrichment",
                    "OTX API connection test succeeded",
                    {"pulse_count": status.get("pulse_count", 0)},
                )
                return {"ok": True, **status}
            except requests.RequestException as exc:
                insert_app_event(conn, "error", "enrichment", f"OTX API connection test failed: {exc}")
                return {"ok": False, "status": "failed", "error": str(exc)}
            except ValueError as exc:
                return {"ok": False, "status": "missing_key", "error": str(exc)}
        finally:
            conn.close()

    @app.get("/api/pcap-files")
    def api_pcap_files(detection_type: str = None):
        conn = connect(db_path)
        try:
            window = detection_time_window(conn, detection_type)
        finally:
            conn.close()
        inventory = list_pcap_files(config, window.get("start_time"), window.get("end_time"))
        inventory["detection_type"] = detection_type
        inventory["time_window"] = window
        return inventory

    @app.get("/api/decision-evidence")
    def api_decision_evidence(limit: int = 25, detection_type: str = None, outcome: str = None):
        if outcome and outcome not in {"safe", "human_review", "dangerous"}:
            raise HTTPException(status_code=400, detail="Unsupported outcome filter")
        conn = connect(db_path)
        try:
            return latest_decision_evidence(conn, limit, detection_type, outcome)
        finally:
            conn.close()

    @app.get("/api/assets")
    def api_assets(limit: int = 100):
        conn = connect(db_path)
        try:
            return {
                "types": default_asset_types(config),
                "default_interface": config.get("assets", {}).get("internal_interface", "ens37"),
                "summary": asset_summary(conn),
                "assets": list_assets(conn, limit),
            }
        finally:
            conn.close()

    @app.post("/api/assets")
    def api_upsert_asset(payload: AssetRequest):
        try:
            ip_address = str(ipaddress.ip_address(payload.ip_address.strip()))
        except ValueError:
            raise HTTPException(status_code=400, detail="Enter a valid IPv4 or IPv6 address")

        name = payload.name.strip()
        if not name:
            raise HTTPException(status_code=400, detail="Asset name is required")

        allowed_types = {item["value"] for item in default_asset_types(config)}
        device_type = payload.device_type.strip()
        if device_type not in allowed_types:
            raise HTTPException(status_code=400, detail="Unsupported device type")

        score = payload.asset_score
        if score is None:
            score = default_asset_score(config, device_type)
        if score < 0 or score > 10:
            raise HTTPException(status_code=400, detail="Asset score must be between 0 and 10")

        conn = connect(db_path)
        try:
            asset_id = upsert_asset(
                conn,
                {
                    "ip_address": ip_address,
                    "name": name,
                    "device_type": device_type,
                    "network_interface": payload.network_interface.strip()
                    or config.get("assets", {}).get("internal_interface", "ens37"),
                    "asset_score": score,
                    "function": payload.function.strip(),
                    "notes": payload.notes.strip(),
                },
            )
            insert_app_event(conn, "info", "assets", f"Saved asset {name} ({ip_address})", {"asset_id": asset_id})
            return {"id": asset_id, "status": "active"}
        finally:
            conn.close()

    @app.delete("/api/assets/{asset_id}")
    def api_deactivate_asset(asset_id: int):
        conn = connect(db_path)
        try:
            if not deactivate_asset(conn, asset_id):
                raise HTTPException(status_code=404, detail="Asset not found")
            insert_app_event(conn, "info", "assets", f"Deactivated asset {asset_id}")
            return {"status": "inactive"}
        finally:
            conn.close()

    @app.get("/api/allowlist")
    def api_allowlist(limit: int = 50):
        conn = connect(db_path)
        try:
            return list_allowlist_entries(conn, limit)
        finally:
            conn.close()

    @app.post("/api/allowlist")
    def api_add_allowlist_entry(payload: AllowlistRequest):
        try:
            ip_address = str(ipaddress.ip_address(payload.ip_address.strip()))
        except ValueError:
            raise HTTPException(status_code=400, detail="Enter a valid IPv4 or IPv6 address")

        if payload.duration_hours < 1:
            raise HTTPException(status_code=400, detail="Duration must be at least 1 hour")
        if payload.duration_hours > 24 * 365:
            raise HTTPException(status_code=400, detail="Duration cannot exceed 365 days")
        if not payload.reason.strip():
            raise HTTPException(status_code=400, detail="Reason is required")

        conn = connect(db_path)
        try:
            entry_id = add_allowlist_entry(
                conn,
                ip_address,
                payload.duration_hours * 60,
                name=payload.name.strip() or None,
                reason=payload.reason.strip(),
                added_by=payload.added_by.strip() or "dashboard",
            )
            insert_app_event(conn, "info", "allowlist", f"Allowlisted {ip_address}", {"entry_id": entry_id})
            return {"id": entry_id, "status": "active"}
        finally:
            conn.close()

    @app.delete("/api/allowlist/{entry_id}")
    def api_deactivate_allowlist_entry(entry_id: int):
        conn = connect(db_path)
        try:
            if not deactivate_allowlist_entry(conn, entry_id):
                raise HTTPException(status_code=404, detail="Allowlist entry not found")
            insert_app_event(conn, "info", "allowlist", f"Deactivated allowlist entry {entry_id}")
            return {"status": "inactive"}
        finally:
            conn.close()

    @app.get("/api/reviews")
    def api_reviews(limit: int = 50):
        conn = connect(db_path)
        try:
            return list_review_queue(conn, limit)
        finally:
            conn.close()

    @app.post("/api/reviews/{detection_id}")
    def api_submit_review(detection_id: int, payload: AnalystReviewRequest):
        action = payload.action.strip().lower()
        if action not in {"confirm", "log_only", "human_review", "would_block", "temporary_block"}:
            raise HTTPException(status_code=400, detail="Unsupported review action")
        if action != "confirm" and payload.score is None:
            raise HTTPException(status_code=400, detail="Override score is required")
        if payload.score is not None and (payload.score < 0 or payload.score > 100):
            raise HTTPException(status_code=400, detail="Score must be between 0 and 100")
        tuning_label = payload.tuning_label.strip()
        if tuning_label and tuning_label not in {"true_positive", "false_positive", "authorized_test", "unknown"}:
            raise HTTPException(status_code=400, detail="Unsupported tuning label")

        conn = connect(db_path)
        try:
            ok = submit_analyst_review(
                conn,
                detection_id,
                action,
                payload.analyst_name.strip() or "analyst",
                notes=payload.notes.strip(),
                score=payload.score,
                classification=payload.classification,
                tuning_label=tuning_label or None,
            )
            if not ok:
                raise HTTPException(status_code=404, detail="Review item not found")
            insert_app_event(conn, "info", "review", f"Analyst submitted review for detection {detection_id}", {"action": action})
            return {"status": "saved"}
        finally:
            conn.close()

    @app.get("/api/events")
    def api_events(limit: int = 100):
        conn = connect(db_path)
        try:
            return latest_app_events(conn, limit)
        finally:
            conn.close()

    @app.post("/api/reset-logs")
    def api_reset_logs(payload: ResetLogsRequest):
        if payload.confirm != "RESET":
            raise HTTPException(status_code=400, detail="Type RESET to clear dashboard logs")
        conn = connect(db_path)
        try:
            counts = reset_dashboard_logs(conn)
            insert_app_event(conn, "warning", "reset", "Dashboard logs were reset", counts)
            return {"status": "reset", "deleted": counts}
        finally:
            conn.close()

    @app.get("/api/ollama-status")
    def api_ollama_status():
        conn = connect(db_path)
        try:
            try:
                status = check_ollama(config)
                insert_app_event(
                    conn,
                    "info",
                    "ollama",
                    f"Ollama reachable at {status['host']}",
                    {"elapsed_ms": status["elapsed_ms"], "models": status["models"]},
                )
                return {"ok": True, **status}
            except requests.RequestException as exc:
                insert_app_event(conn, "error", "ollama", f"Ollama unreachable: {exc}")
                return {"ok": False, "error": str(exc), "host": config.get("ollama", {}).get("host")}
        finally:
            conn.close()

    @app.get("/api/metrics")
    def api_metrics():
        conn = connect(db_path)
        try:
            total_alerts = conn.execute("SELECT COUNT(*) AS count FROM alerts").fetchone()["count"]
            total_detections = conn.execute("SELECT COUNT(*) AS count FROM detections").fetchone()["count"]
            total_assets = conn.execute("SELECT COUNT(*) AS count FROM assets WHERE status = 'active'").fetchone()["count"]
            by_type = conn.execute(
                "SELECT detection_type, COUNT(*) AS count FROM detections GROUP BY detection_type ORDER BY count DESC"
            ).fetchall()
            by_classification = conn.execute(
                """
                SELECT final_classification, final_action, COUNT(*) AS count
                FROM responses
                GROUP BY final_classification, final_action
                """
            ).fetchall()
            outcome_counts = {
                "safe": 0,
                "human_review": 0,
                "dangerous": 0,
            }
            for row in by_classification:
                classification = str(row["final_classification"] or "").lower()
                action = str(row["final_action"] or "").lower()
                count = row["count"]
                if "dangerous" in classification or action in {"would_block", "temporary_block"}:
                    outcome_counts["dangerous"] += count
                elif "human" in classification or action == "human_review":
                    outcome_counts["human_review"] += count
                else:
                    outcome_counts["safe"] += count
            return {
                "total_alerts": total_alerts,
                "total_detections": total_detections,
                "total_assets": total_assets,
                "outcome_counts": outcome_counts,
                "detections_by_type": [dict(row) for row in by_type],
                "mode": config.get("system", {}).get("mode"),
            }
        finally:
            conn.close()

    return app

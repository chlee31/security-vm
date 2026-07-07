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
    ai_model_comparison,
    asset_summary,
    connect,
    create_ai_profile,
    deactivate_asset,
    delete_asset,
    default_asset_score,
    default_asset_types,
    ensure_ai_profile_from_config,
    get_ai_profile,
    init_db,
    insert_app_event,
    detection_type_detail,
    detection_time_window,
    enrichment_status,
    investigation_detail,
    latest_alerts,
    latest_app_events,
    latest_decision_evidence,
    latest_ollama_reports,
    list_incident_evidence,
    list_ai_profiles,
    list_all_assets,
    list_assets,
    list_review_queue,
    mark_ai_profile_selected,
    public_ips_for_enrichment,
    reset_dashboard_logs,
    submit_analyst_review,
    upsert_threat_intel_lookup,
    upsert_asset,
    update_asset,
    update_ai_profile,
)
from app.enrichment import lookup_otx_ip, test_otx_connection
from app.ollama_client import check_ollama, model_metadata
from app.pcap_inventory import list_pcap_files


STATIC_DIR = Path(__file__).resolve().parents[1] / "static"
NO_CACHE_HEADERS = {"Cache-Control": "no-store, max-age=0"}


def static_page(filename):
    return FileResponse(STATIC_DIR / filename, headers=NO_CACHE_HEADERS)


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
    provider: str = ""
    timeout_seconds: int = 90


class AIProfileRequest(OllamaConfigRequest):
    name: str
    status: str = "active"
    notes: str = ""


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
    provider = payload.provider.strip().lower().replace(" ", "_")
    parsed = urlparse(host)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(status_code=400, detail="AI service URL must look like http://IP:11434")
    if not model:
        raise HTTPException(status_code=400, detail="AI model name is required")
    if payload.timeout_seconds < 5 or payload.timeout_seconds > 300:
        raise HTTPException(status_code=400, detail="Timeout must be between 5 and 300 seconds")
    return host, model, provider, payload.timeout_seconds


def validate_ai_profile(payload):
    host, model, provider, timeout_seconds = validate_ollama_config(payload)
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="AI profile name is required")
    status = payload.status.strip().lower()
    if status not in {"active", "inactive"}:
        raise HTTPException(status_code=400, detail="AI profile status must be active or inactive")
    return {
        "name": name,
        "host": host,
        "model": model,
        "provider": provider,
        "timeout_seconds": timeout_seconds,
        "status": status,
        "notes": payload.notes.strip(),
    }


def apply_ai_profile_to_config(config, profile):
    config.setdefault("ollama", {})
    config["ollama"]["active_profile_uid"] = profile["uid"]
    config["ollama"]["host"] = profile["host"]
    config["ollama"]["model"] = profile["model"]
    config["ollama"]["provider"] = profile["provider"]
    config["ollama"]["timeout_seconds"] = int(profile.get("timeout_seconds") or 90)


def create_app(config_path):
    config = load_config(config_path)
    db_path = config.get("database", {}).get("path", "security_vm.db")
    init_db(db_path).close()
    app = FastAPI(title="Security VM Dashboard")
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/")
    def index():
        return static_page("index.html")

    @app.get("/detection")
    def detection_workbook():
        return static_page("detection.html")

    @app.get("/outcome")
    def outcome_workbook():
        return static_page("outcome.html")

    @app.get("/investigation")
    def investigation_workbook():
        return static_page("investigation.html")

    @app.get("/compare")
    def ai_comparison_workbook():
        return static_page("compare.html")

    @app.get("/asset-inventory")
    def asset_inventory_workbook():
        return static_page("asset_inventory.html")

    @app.get("/assets")
    def legacy_asset_inventory_workbook():
        return static_page("asset_inventory.html")

    @app.get("/admin")
    def admin_controls():
        return static_page("admin.html")

    @app.get("/api/admin/settings")
    def api_admin_settings(limit: int = 500):
        conn = connect(db_path)
        try:
            profile_uid = ensure_ai_profile_from_config(conn, config)
            save_config(config, config_path)
            metadata = model_metadata(config)
            return {
                "config_path": str(config_path),
                "database_path": db_path,
                "ollama": {
                    "active_profile_uid": profile_uid,
                    "host": config.get("ollama", {}).get("host", ""),
                    "model": config.get("ollama", {}).get("model", ""),
                    "provider": config.get("ollama", {}).get("provider", ""),
                    "timeout_seconds": config.get("ollama", {}).get("timeout_seconds", 90),
                    "model_suggestions": OLLAMA_MODEL_SUGGESTIONS,
                    "metadata": metadata,
                },
                "ai_profiles": {
                    "active_uid": profile_uid,
                    "items": list_ai_profiles(conn, limit),
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
        host, model, provider, timeout_seconds = validate_ollama_config(payload)
        config.setdefault("ollama", {})
        config["ollama"]["host"] = host
        config["ollama"]["model"] = model
        config["ollama"]["provider"] = provider
        config["ollama"]["timeout_seconds"] = timeout_seconds

        conn = connect(db_path)
        try:
            profile = {
                "name": f"{provider or 'ai'}:{model}",
                "host": host,
                "model": model,
                "provider": provider or "ai_service",
                "timeout_seconds": timeout_seconds,
                "status": "active",
                "notes": "Updated from legacy AI settings form.",
            }
            active_uid = config.get("ollama", {}).get("active_profile_uid")
            if active_uid and get_ai_profile(conn, active_uid):
                update_ai_profile(conn, active_uid, profile)
                profile_uid = active_uid
            else:
                profile_uid = create_ai_profile(conn, profile)
            saved_profile = get_ai_profile(conn, profile_uid)
            apply_ai_profile_to_config(config, saved_profile)
            mark_ai_profile_selected(conn, profile_uid)
            save_config(config, config_path)
            insert_app_event(
                conn,
                "info",
                "admin",
                f"Updated AI model settings to profile {profile_uid}",
                {"ai_profile_uid": profile_uid, "host": host, "model": model, "provider": provider, "timeout_seconds": timeout_seconds},
            )
        finally:
            conn.close()
        return {"status": "saved", "host": host, "model": model, "provider": provider, "timeout_seconds": timeout_seconds, "ai_profile_uid": profile_uid}

    @app.post("/api/admin/ai-profiles")
    def api_admin_create_ai_profile(payload: AIProfileRequest):
        profile = validate_ai_profile(payload)
        conn = connect(db_path)
        try:
            uid = create_ai_profile(conn, profile)
            saved = get_ai_profile(conn, uid)
            if saved.get("status") == "active":
                apply_ai_profile_to_config(config, saved)
                mark_ai_profile_selected(conn, uid)
                save_config(config, config_path)
            insert_app_event(
                conn,
                "info",
                "admin",
                f"Created AI profile {saved['name']} ({uid})",
                {"ai_profile_uid": uid, "model": saved["model"], "provider": saved["provider"]},
            )
            return {"status": "created", "profile": saved}
        finally:
            conn.close()

    @app.put("/api/admin/ai-profiles/{profile_uid}")
    def api_admin_update_ai_profile(profile_uid: str, payload: AIProfileRequest):
        profile = validate_ai_profile(payload)
        conn = connect(db_path)
        try:
            if not update_ai_profile(conn, profile_uid, profile):
                raise HTTPException(status_code=404, detail="AI profile not found")
            saved = get_ai_profile(conn, profile_uid)
            if config.get("ollama", {}).get("active_profile_uid") == profile_uid:
                apply_ai_profile_to_config(config, saved)
                save_config(config, config_path)
            insert_app_event(
                conn,
                "info",
                "admin",
                f"Updated AI profile {saved['name']} ({profile_uid})",
                {"ai_profile_uid": profile_uid, "model": saved["model"], "provider": saved["provider"]},
            )
            return {"status": "saved", "profile": saved}
        finally:
            conn.close()

    @app.post("/api/admin/ai-profiles/{profile_uid}/select")
    def api_admin_select_ai_profile(profile_uid: str):
        conn = connect(db_path)
        try:
            profile = get_ai_profile(conn, profile_uid)
            if not profile:
                raise HTTPException(status_code=404, detail="AI profile not found")
            if profile.get("status") != "active":
                raise HTTPException(status_code=400, detail="Inactive AI profiles cannot be selected")
            apply_ai_profile_to_config(config, profile)
            mark_ai_profile_selected(conn, profile_uid)
            save_config(config, config_path)
            insert_app_event(
                conn,
                "info",
                "admin",
                f"Selected AI profile {profile['name']} ({profile_uid})",
                {"ai_profile_uid": profile_uid, "model": profile["model"], "provider": profile["provider"]},
            )
            return {"status": "selected", "profile": profile}
        finally:
            conn.close()

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

    @app.get("/api/ai-model-comparison")
    def api_ai_model_comparison():
        conn = connect(db_path)
        try:
            return ai_model_comparison(conn)
        finally:
            conn.close()

    @app.get("/api/detection-detail")
    def api_detection_detail(detection_type: str = None, limit: int = 50):
        conn = connect(db_path)
        try:
            return detection_type_detail(conn, detection_type, limit)
        finally:
            conn.close()

    @app.get("/api/dashboard-summary")
    def api_dashboard_summary(limit: int = 12):
        conn = connect(db_path)
        try:
            detail = detection_type_detail(conn, None, limit)
            comparison = ai_model_comparison(conn)
            enrichment = enrichment_status(conn, config, limit)
            active_uid = config.get("ollama", {}).get("active_profile_uid")
            active_profile = get_ai_profile(conn, active_uid) if active_uid else None
            otx_rows = conn.execute(
                """
                SELECT
                  COALESCE(reputation, 'unknown') AS reputation,
                  COUNT(*) AS count,
                  SUM(COALESCE(malicious_count, 0)) AS malicious_total,
                  SUM(COALESCE(suspicious_count, 0)) AS suspicious_total
                FROM threat_intel_lookups
                WHERE source = 'otx'
                GROUP BY COALESCE(reputation, 'unknown')
                ORDER BY count DESC
                """
            ).fetchall()
            otx_lookup_rows = conn.execute(
                """
                SELECT indicator, indicator_type, COALESCE(reputation, 'unknown') AS reputation,
                       malicious_count, suspicious_count, lookup_result, lookup_time, cached
                FROM threat_intel_lookups
                WHERE source = 'otx'
                ORDER BY reputation ASC, lookup_time DESC, id DESC
                LIMIT ?
                """,
                (max(50, limit * 10),),
            ).fetchall()
            otx_by_reputation = {}
            seen_indicators = set()
            for row in otx_lookup_rows:
                item = dict(row)
                key = (item.get("reputation"), item.get("indicator"))
                if key in seen_indicators:
                    continue
                seen_indicators.add(key)
                otx_by_reputation.setdefault(item.get("reputation") or "unknown", []).append(item)
            review_rows = conn.execute(
                """
                SELECT review_status, COUNT(*) AS count
                FROM analyst_reviews
                GROUP BY review_status
                ORDER BY count DESC
                """
            ).fetchall()
            return {
                "timeline": detail.get("timeline", [])[-8:],
                "top_ips": detail.get("ips", [])[:limit],
                "otx": {
                    "lookup_count": enrichment.get("lookup_count", 0),
                    "sources": enrichment.get("sources", []),
                    "by_reputation": [dict(row) for row in otx_rows],
                    "lookups_by_reputation": otx_by_reputation,
                    "recent_lookups": enrichment.get("recent_lookups", [])[:limit],
                },
                "model_comparison": comparison,
                "active_ai_profile": active_profile,
                "review_status": [dict(row) for row in review_rows],
            }
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

    @app.get("/api/investigation/{detection_id}")
    def api_investigation(detection_id: int):
        conn = connect(db_path)
        try:
            detail = investigation_detail(conn, detection_id)
            if not detail:
                raise HTTPException(status_code=404, detail="Investigation not found")
            incident_evidence = list_incident_evidence(conn, detection_id)
        finally:
            conn.close()
        pcaps = list_pcap_files(config, detail.get("timestamp") or detail.get("first_seen"), detail.get("last_seen") or detail.get("timestamp"))
        pcaps["detection_id"] = detection_id
        pcaps["incident_evidence"] = incident_evidence
        detail["pcap_files"] = pcaps
        detail["incident_evidence"] = incident_evidence
        return detail

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

    @app.get("/api/asset-inventory")
    def api_asset_inventory(limit: int = 500):
        conn = connect(db_path)
        try:
            assets = list_all_assets(conn, limit)
            type_rows = conn.execute(
                """
                SELECT device_type, status, COUNT(*) AS count, AVG(asset_score) AS avg_score
                FROM assets
                GROUP BY device_type, status
                ORDER BY count DESC, device_type ASC
                """
            ).fetchall()
            score_rows = conn.execute(
                """
                SELECT asset_score, COUNT(*) AS count
                FROM assets
                WHERE status = 'active'
                GROUP BY asset_score
                ORDER BY asset_score DESC
                """
            ).fetchall()
            match_rows = conn.execute(
                """
                SELECT ip_address, SUM(source_matches) AS source_matches, SUM(destination_matches) AS destination_matches
                FROM (
                  SELECT assets.ip_address, COUNT(detections.id) AS source_matches, 0 AS destination_matches
                  FROM assets
                  LEFT JOIN detections ON detections.src_ip = assets.ip_address
                  GROUP BY assets.ip_address
                  UNION ALL
                  SELECT assets.ip_address, 0 AS source_matches, COUNT(detections.id) AS destination_matches
                  FROM assets
                  LEFT JOIN detections ON detections.dest_ip = assets.ip_address
                  GROUP BY assets.ip_address
                )
                GROUP BY ip_address
                """
            ).fetchall()
            matches_by_ip = {
                row["ip_address"]: {
                    "source_matches": row["source_matches"] or 0,
                    "destination_matches": row["destination_matches"] or 0,
                    "total_matches": (row["source_matches"] or 0) + (row["destination_matches"] or 0),
                }
                for row in match_rows
            }
            recent_rows = conn.execute(
                """
                SELECT
                  detections.id AS detection_id,
                  detections.src_ip,
                  detections.dest_ip,
                  detections.detection_type,
                  detections.python_initial_score,
                  detections.created_at,
                  alerts.signature,
                  responses.final_classification,
                  responses.final_score
                FROM detections
                LEFT JOIN alerts ON alerts.id = detections.first_alert_id
                LEFT JOIN responses ON responses.detection_id = detections.id
                WHERE detections.src_ip IN (SELECT ip_address FROM assets)
                   OR detections.dest_ip IN (SELECT ip_address FROM assets)
                ORDER BY detections.id DESC
                LIMIT 50
                """
            ).fetchall()
            recent_by_ip = {}
            for row in recent_rows:
                item = dict(row)
                for ip_address in {item.get("src_ip"), item.get("dest_ip")}:
                    if ip_address:
                        recent_by_ip.setdefault(ip_address, []).append(item)

            enriched_assets = []
            for asset in assets:
                item = dict(asset)
                item["matches"] = matches_by_ip.get(
                    item["ip_address"],
                    {"source_matches": 0, "destination_matches": 0, "total_matches": 0},
                )
                item["recent_detections"] = recent_by_ip.get(item["ip_address"], [])[:6]
                enriched_assets.append(item)

            active_assets = [asset for asset in enriched_assets if asset.get("status") == "active"]
            internal_interface = config.get("assets", {}).get("internal_interface", "ens37")
            summary = asset_summary(conn)
            summary.update(
                {
                    "inactive": len([asset for asset in enriched_assets if asset.get("status") == "inactive"]),
                    "high_value": len([asset for asset in active_assets if int(asset.get("asset_score") or 0) >= 8]),
                    "internal_interface_count": len(
                        [
                            asset
                            for asset in active_assets
                            if (asset.get("network_interface") or internal_interface) == internal_interface
                        ]
                    ),
                }
            )
            return {
                "types": default_asset_types(config),
                "default_interface": internal_interface,
                "summary": summary,
                "by_type": [dict(row) for row in type_rows],
                "by_score": [dict(row) for row in score_rows],
                "assets": enriched_assets,
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
                    "ai_model",
                    f"AI model reachable at {status['host']}",
                    {"elapsed_ms": status["elapsed_ms"], "models": status["models"]},
                )
                return {"ok": True, **status}
            except requests.RequestException as exc:
                insert_app_event(conn, "error", "ai_model", f"AI model unreachable: {exc}")
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

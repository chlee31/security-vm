from pathlib import Path
import importlib.util
import getpass
import ipaddress
import json
import os
import shutil
import sqlite3
import subprocess
import sys
from typing import Dict, List, Optional
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
import requests
from pydantic import BaseModel

from app.allowlist import add_allowlist_entry, deactivate_allowlist_entry, deactivate_allowlist_for_ip, list_allowlist_entries
from app.config import load_config, save_config
from app.database import (
    ai_comparison_detail,
    ai_comparison_scorecard,
    ai_model_comparison,
    asset_summary,
    case_workspace,
    connect,
    create_ai_profile,
    deactivate_asset,
    delete_asset,
    delete_ai_profile,
    default_asset_score,
    default_asset_types,
    ensure_ai_profile_from_config,
    get_ai_profile,
    init_db,
    insert_app_event,
    detection_type_detail,
    detection_time_window,
    enrichment_status,
    get_firewall_candidate,
    get_firewall_block,
    ip_detail,
    investigation_detail,
    latest_alerts,
    latest_sensor_alerts,
    latest_app_events,
    latest_decision_evidence,
    latest_ai_opinions,
    latest_zeek_events,
    insert_firewall_block,
    insert_notification_event,
    list_ai_profiles,
    list_ai_comparison_runs,
    list_all_assets,
    list_firewall_candidates,
    list_firewall_history,
    list_firewall_blocks,
    list_notification_events,
    list_review_queue,
    mark_ai_profile_selected,
    public_ips_for_enrichment,
    release_firewall_block,
    reset_dashboard_logs,
    submit_analyst_review,
    update_response_manual_action,
    upsert_threat_intel_lookup,
    upsert_asset,
    update_asset,
    update_ai_profile,
    vote_ai_comparison,
    zeek_context_for_detection,
    zeek_event_counts,
    zeek_telemetry_summary,
)
from app.bootstrap import detect_os_release, zeek_os_recommendation
from app.enrichment import lookup_otx_ip, test_otx_connection
from app.threat_intel import (
    PROVIDERS,
    provider_config,
    provider_evidence_for_indicator,
    refresh_provider,
    sanitized_provider_status,
)
from app.firewall import firewalld_runtime_status, firewalld_setup_commands, remove_firewalld_block, temporary_block_firewalld
from app.incident_evidence import create_incident_evidence
from app.ai_client import check_ai_model, model_metadata
from app.ai_comparison import run_model_comparison
from app.case_assessment import reassess_case, refresh_case_virustotal
from app.notifications import normalize_recipients, sanitized_email_settings, send_email
from app.security import redact_secrets
from app.pcap_inventory import list_pcap_files
from app.zeek_inventory import zeek_status


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


class AIModelConfigRequest(BaseModel):
    host: str
    model: str
    provider: str = ""
    timeout_seconds: int = 90


class AIProfileRequest(AIModelConfigRequest):
    name: str
    status: str = "active"
    notes: str = ""


class AIComparisonSettingsRequest(BaseModel):
    profile_uids: List[str]


class AIComparisonVoteRequest(BaseModel):
    analyst_name: str = "analyst"
    selection: str
    notes: str = ""


class ResetLogsRequest(BaseModel):
    confirm: str


class ThreatIntelConfigRequest(BaseModel):
    otx_enabled: bool = False
    otx_api_key: str = ""
    cache_ttl_hours: int = 24


class ThreatIntelProviderRequest(BaseModel):
    enabled: bool = False
    api_key: str = ""
    refresh_hours: int = 24


class ThreatIntelAdminRequest(BaseModel):
    providers: Dict[str, ThreatIntelProviderRequest]


class SystemModeRequest(BaseModel):
    mode: str


class FirewallBlockActionRequest(BaseModel):
    analyst_name: str = "admin"
    reason: str = ""
    safe_duration_hours: int = 24 * 365


class OtxLookupRequest(BaseModel):
    limit: int = 5
    scope: str = "top5"
    detection_type: Optional[str] = None


class OtxStatusRequest(BaseModel):
    otx_api_key: str = ""


class EmailNotificationRequest(BaseModel):
    enabled: bool = False
    sender: str = ""
    app_password: str = ""
    recipients: str = ""
    cooldown_minutes: int = 15
    dashboard_base_url: str = ""


class InvestigationRequest(BaseModel):
    seconds_before: int = 120
    seconds_after: int = 120
    ip_filter_enabled: bool = True


ADMIN_SYSTEM_TOOLS = {
    "Python": {"binary": "python3", "package": "python3 python3-venv python3-pip"},
    "Suricata": {"binary": "suricata", "package": "suricata"},
    "Suricata Update": {"binary": "suricata-update", "package": "suricata-update"},
    "SQLite CLI": {"binary": "sqlite3", "package": "sqlite3"},
    "curl": {"binary": "curl", "package": "curl"},
    "Tailscale": {"binary": "tailscale", "package": "tailscale"},
    "Zeek": {
        "binary": "zeek",
        "package": "zeek",
        "candidates": ["zeek", "/opt/zeek/bin/zeek", "/usr/local/bin/zeek"],
    },
    "ZeekControl": {
        "binary": "zeekctl",
        "package": "zeek",
        "candidates": ["zeekctl", "/opt/zeek/bin/zeekctl", "/usr/local/bin/zeekctl"],
    },
    "Zeek Package Manager": {
        "binary": "zkg",
        "package": "zeek",
        "candidates": ["zkg", "/opt/zeek/bin/zkg", "/usr/local/bin/zkg"],
    },
}

ADMIN_PYTHON_PACKAGES = {
    "FastAPI": {"module": "fastapi", "package": "fastapi", "distribution": "fastapi"},
    "Uvicorn": {"module": "uvicorn", "package": "uvicorn", "distribution": "uvicorn"},
    "PyYAML": {"module": "yaml", "package": "PyYAML", "distribution": "PyYAML"},
    "Requests": {"module": "requests", "package": "requests", "distribution": "requests"},
}

AI_MODEL_SUGGESTIONS = [
    "llama3.1:8b",
    "llama3.2:latest",
    "deepseek-r1:8b",
    "deepseek-r1:latest",
]

ENCRYPTED_TRAFFIC_PORTS = (22, 443, 853, 8443, 1194, 500, 4500, 51820)
ENCRYPTED_TRAFFIC_KEYWORDS = ("tls", "ssl", "https", "quic", "vpn", "wireguard", "openvpn", "ipsec", "ssh")


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
            path = ""
            for candidate in meta.get("candidates", [binary]):
                resolved = shutil.which(candidate, mode=os.F_OK) if "/" not in candidate else candidate
                if resolved and Path(resolved).exists():
                    path = str(resolved)
                    break
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


def encrypted_traffic_summary(conn, limit=8):
    port_placeholders = ",".join("?" for _ in ENCRYPTED_TRAFFIC_PORTS)
    keyword_sql = " OR ".join(
        [
            "LOWER(COALESCE(alerts.signature, '')) LIKE ?",
            "LOWER(COALESCE(alerts.category, '')) LIKE ?",
            "LOWER(COALESCE(detections.detection_type, '')) LIKE ?",
        ]
        * len(ENCRYPTED_TRAFFIC_KEYWORDS)
    )
    keyword_params = []
    for keyword in ENCRYPTED_TRAFFIC_KEYWORDS:
        pattern = f"%{keyword}%"
        keyword_params.extend([pattern, pattern, pattern])
    where_sql = f"""
      (
        CAST(COALESCE(alerts.dest_port, 0) AS INTEGER) IN ({port_placeholders})
        OR CAST(COALESCE(alerts.src_port, 0) AS INTEGER) IN ({port_placeholders})
        OR {keyword_sql}
      )
    """
    params = list(ENCRYPTED_TRAFFIC_PORTS) + list(ENCRYPTED_TRAFFIC_PORTS) + keyword_params

    total = conn.execute(
        f"""
        SELECT COUNT(DISTINCT detections.id) AS count
        FROM detections
        LEFT JOIN alerts ON alerts.id = detections.first_alert_id
        WHERE {where_sql}
        """,
        params,
    ).fetchone()

    port_case_sql = f"""
      CASE
        WHEN CAST(COALESCE(alerts.dest_port, 0) AS INTEGER) IN ({port_placeholders}) THEN alerts.dest_port
        WHEN CAST(COALESCE(alerts.src_port, 0) AS INTEGER) IN ({port_placeholders}) THEN alerts.src_port
        ELSE COALESCE(alerts.dest_port, alerts.src_port, 'metadata')
      END
    """
    port_case_params = list(ENCRYPTED_TRAFFIC_PORTS) + list(ENCRYPTED_TRAFFIC_PORTS)

    ports = conn.execute(
        f"""
        SELECT protocol, port, COUNT(*) AS count
        FROM (
          SELECT
            COALESCE(alerts.protocol, 'unknown') AS protocol,
            {port_case_sql} AS port
          FROM detections
          LEFT JOIN alerts ON alerts.id = detections.first_alert_id
          WHERE {where_sql}
        )
        GROUP BY protocol, port
        ORDER BY count DESC
        LIMIT ?
        """,
        port_case_params + params + [limit],
    ).fetchall()

    ips = conn.execute(
        f"""
        SELECT ip_address, COUNT(*) AS count
        FROM (
          SELECT detections.src_ip AS ip_address
          FROM detections
          LEFT JOIN alerts ON alerts.id = detections.first_alert_id
          WHERE {where_sql} AND detections.src_ip IS NOT NULL
          UNION ALL
          SELECT detections.dest_ip AS ip_address
          FROM detections
          LEFT JOIN alerts ON alerts.id = detections.first_alert_id
          WHERE {where_sql} AND detections.dest_ip IS NOT NULL
        )
        GROUP BY ip_address
        ORDER BY count DESC
        LIMIT ?
        """,
        params + params + [limit],
    ).fetchall()

    return {
        "candidate_count": total["count"] if total else 0,
        "ports": [dict(row) for row in ports],
        "ips": [dict(row) for row in ips],
        "visible": [
            "IPs",
            "ports",
            "protocol",
            "DNS/TLS hints",
            "timing",
            "volume",
            "reputation",
        ],
        "not_visible": "Encrypted payload contents without endpoint telemetry or TLS inspection.",
    }


def validate_ai_model_config(payload):
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
    host, model, provider, timeout_seconds = validate_ai_model_config(payload)
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
    config.setdefault("ai_model", {})
    config["ai_model"]["active_profile_uid"] = profile["uid"]
    config["ai_model"]["host"] = profile["host"]
    config["ai_model"]["model"] = profile["model"]
    config["ai_model"]["provider"] = profile["provider"]
    config["ai_model"]["timeout_seconds"] = int(profile.get("timeout_seconds") or 90)


def validate_email_notifications(payload, existing=None, require_credentials=False):
    existing = existing or {}
    sender = payload.sender.strip()
    recipients = normalize_recipients(payload.recipients)
    app_password = payload.app_password.replace(" ", "").strip() or existing.get("app_password", "")
    credentials_required = payload.enabled or require_credentials
    if credentials_required:
        if "@" not in sender:
            raise HTTPException(status_code=400, detail="Gmail sender address is required")
        if not recipients:
            raise HTTPException(status_code=400, detail="Add at least one recipient email address")
        if not app_password:
            raise HTTPException(status_code=400, detail="Gmail app password is required when email alerts are enabled")
        if len(app_password) != 16:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Gmail app password should be 16 characters after removing spaces. "
                    f"The saved/provided value is {len(app_password)} characters."
                ),
            )
    if payload.cooldown_minutes < 0 or payload.cooldown_minutes > 1440:
        raise HTTPException(status_code=400, detail="Cooldown must be between 0 and 1440 minutes")
    return {
        "enabled": bool(payload.enabled),
        "provider": "gmail",
        "smtp_host": "smtp.gmail.com",
        "smtp_port": 587,
        "use_starttls": True,
        "sender": sender,
        "username": sender,
        "app_password": app_password,
        "recipients": recipients,
        "cooldown_minutes": payload.cooldown_minutes,
        "dangerous_only": True,
        "dashboard_base_url": payload.dashboard_base_url.strip(),
    }


def create_app(config_path):
    config = load_config(config_path)
    db_path = config.get("database", {}).get("path", "security_vm.db")
    init_db(db_path).close()
    app = FastAPI(title="Security VM Dashboard")
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.middleware("http")
    async def add_no_cache_headers(request, call_next):
        retired_paths = {
            "/api/admin/system-mode",
            "/api/asset-inventory",
            "/api/pcap-files",
        }
        retired_prefixes = (
            "/api/admin/notifications/",
            "/api/admin/firewall-",
            "/api/assets",
            "/api/allowlist",
            "/api/incident-evidence/",
        )
        path = request.url.path
        retired_detection_path = path.startswith("/api/detections/") and (
            path.endswith("/investigation") or path.endswith("/incident-evidence")
        )
        if path in retired_paths or path.startswith(retired_prefixes) or retired_detection_path:
            return JSONResponse(
                status_code=410,
                content={
                    "detail": "This endpoint was retired when Security VM moved to passive case analysis."
                },
            )
        response = await call_next(request)
        if request.url.path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-store, max-age=0"
        return response

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

    @app.get("/ip")
    def ip_workbook():
        return static_page("ip.html")

    @app.get("/compare")
    def ai_comparison_workbook():
        return static_page("compare.html")

    @app.get("/zeek")
    def zeek_telemetry_workbook():
        return static_page("zeek.html")

    @app.get("/asset-inventory")
    def asset_inventory_workbook():
        return RedirectResponse(url="/admin#settings", status_code=307)

    @app.get("/assets")
    def legacy_asset_inventory_workbook():
        return RedirectResponse(url="/admin#settings", status_code=307)

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
                "ai_model": {
                    "active_profile_uid": profile_uid,
                    "host": config.get("ai_model", {}).get("host", ""),
                    "model": config.get("ai_model", {}).get("model", ""),
                    "provider": config.get("ai_model", {}).get("provider", ""),
                    "timeout_seconds": config.get("ai_model", {}).get("timeout_seconds", 90),
                    "model_suggestions": AI_MODEL_SUGGESTIONS,
                    "metadata": metadata,
                },
                "ai_profiles": {
                    "active_uid": profile_uid,
                    "items": list_ai_profiles(conn, limit),
                },
                "ai_comparison": {
                    "profile_uids": config.get("ai_comparison", {}).get("profile_uids", []),
                    "candidate_count": 3,
                    "sequential": True,
                },
                "system": {
                    "mode": "analysis",
                    "available_modes": [],
                },
                "firewall": {
                    "provider": "retired",
                    "block_timeout_seconds": 0,
                    "runtime": {},
                    "setup_commands": [],
                    "blocks": [],
                    "candidates": [],
                    "history": [],
                },
                "notifications": {
                    "email": {"enabled": False, "recipients": []},
                    "events": [],
                },
                "network": {
                    "internal_interface": config.get("assets", {}).get("internal_interface", "ens37"),
                    "suricata_eve_json_path": config.get("suricata", {}).get("eve_json_path", ""),
                    "zeek_interface": config.get("zeek", {}).get("interface", ""),
                    "zeek_log_directory": config.get("zeek", {}).get("log_directory", ""),
                },
                "host_os": zeek_os_recommendation(detect_os_release()),
                "assets": {
                    "types": default_asset_types(config),
                    "summary": asset_summary(conn),
                    "items": list_all_assets(conn, limit),
                },
                "threat_intel": {
                    "providers": sanitized_provider_status(config, conn),
                },
                "tools": tool_status(),
                "python_packages": python_package_status(),
            }
        finally:
            conn.close()

    @app.put("/api/admin/threat-intel")
    def api_admin_threat_intel(payload: ThreatIntelAdminRequest):
        threat_intel = config.setdefault("threat_intel", {})
        configured = threat_intel.setdefault("providers", {})
        for source, request in payload.providers.items():
            if source not in PROVIDERS:
                raise HTTPException(status_code=400, detail=f"Unknown threat-intelligence provider: {source}")
            if request.refresh_hours < 1 or request.refresh_hours > 168:
                raise HTTPException(status_code=400, detail=f"{source} refresh interval must be between 1 and 168 hours")
            existing = configured.get(source, {})
            key = request.api_key.strip() or existing.get("api_key", "")
            configured[source] = {
                "enabled": request.enabled,
                "api_key": key,
                "refresh_hours": request.refresh_hours,
            }
            if source in {"otx", "virustotal"}:
                threat_intel[f"{source}_enabled"] = request.enabled
                threat_intel[f"{source}_api_key"] = key
        save_config(config, config_path)
        conn = connect(db_path)
        try:
            insert_app_event(conn, "info", "threat_intel", "Updated threat-intelligence provider settings")
            return {"status": "saved", "providers": sanitized_provider_status(config, conn)}
        finally:
            conn.close()

    @app.put("/api/admin/ai-comparison")
    def api_admin_ai_comparison(payload: AIComparisonSettingsRequest):
        profile_uids = list(dict.fromkeys(uid.strip() for uid in payload.profile_uids if uid.strip()))
        if len(profile_uids) != 3:
            raise HTTPException(status_code=400, detail="Select exactly three different AI profiles")
        conn = connect(db_path)
        try:
            for uid in profile_uids:
                profile = get_ai_profile(conn, uid)
                if not profile:
                    raise HTTPException(status_code=404, detail=f"AI profile {uid} was not found")
                if profile.get("status") != "active":
                    raise HTTPException(status_code=400, detail=f"AI profile {uid} is inactive")
            config.setdefault("ai_comparison", {})["profile_uids"] = profile_uids
            config["ai_comparison"]["candidate_count"] = 3
            config["ai_comparison"]["sequential"] = True
            save_config(config, config_path)
            insert_app_event(
                conn,
                "info",
                "ai_comparison",
                "Updated AI comparison profiles",
                {"profile_count": 3, "sequential": True},
            )
            return {"status": "saved", "profile_uids": profile_uids, "sequential": True}
        finally:
            conn.close()

    @app.post("/api/admin/threat-intel/{source}/refresh")
    def api_admin_refresh_threat_intel(source: str):
        conn = connect(db_path)
        try:
            try:
                result = refresh_provider(conn, config, source)
                insert_app_event(conn, "info", "threat_intel", f"Refreshed {source}", result)
                return result
            except Exception as exc:
                error = redact_secrets(exc, config)
                insert_app_event(conn, "error", "threat_intel", f"{source} refresh failed: {error}")
                raise HTTPException(status_code=400, detail=error)
        finally:
            conn.close()

    @app.post("/api/admin/threat-intel/refresh-active")
    def api_admin_refresh_active_threat_intel():
        conn = connect(db_path)
        results = []
        try:
            for source in PROVIDERS:
                settings = provider_config(config, source)
                if not settings["enabled"] or source not in {"threatfox", "urlhaus", "sslbl", "spamhaus_drop", "openphish", "ipsum", "feodo"}:
                    continue
                try:
                    results.append(refresh_provider(conn, config, source))
                except Exception as exc:
                    results.append({"source": source, "status": "failed", "error": redact_secrets(exc, config)})
            return {"status": "complete", "results": results}
        finally:
            conn.close()

    @app.post("/api/admin/system-mode")
    def api_admin_system_mode(payload: SystemModeRequest):
        mode = payload.mode.strip().lower()
        if mode == "auto_response":
            mode = "prevention"
        if mode not in {"alert_only", "detection", "prevention"}:
            raise HTTPException(status_code=400, detail="Mode must be alert_only, detection, or prevention")
        config.setdefault("system", {})
        config["system"]["mode"] = mode
        save_config(config, config_path)
        conn = connect(db_path)
        try:
            insert_app_event(conn, "warning" if mode == "prevention" else "info", "admin", f"System mode changed to {mode}")
        finally:
            conn.close()
        return {"status": "saved", "mode": mode}

    @app.post("/api/admin/notifications/email")
    def api_admin_email_notifications(payload: EmailNotificationRequest):
        config.setdefault("notifications", {})
        existing = config["notifications"].get("email", {})
        settings = validate_email_notifications(payload, existing)
        config["notifications"]["email"] = settings
        save_config(config, config_path)
        conn = connect(db_path)
        try:
            insert_app_event(
                conn,
                "info",
                "notifications",
                f"Gmail alerts {'enabled' if settings['enabled'] else 'disabled'}",
                {
                    "sender": settings["sender"],
                    "recipient_count": len(settings["recipients"]),
                    "cooldown_minutes": settings["cooldown_minutes"],
                },
            )
        finally:
            conn.close()
        return {"status": "saved", "email": sanitized_email_settings(config)}

    @app.post("/api/admin/notifications/email/test")
    def api_admin_test_email_notifications(payload: EmailNotificationRequest):
        config.setdefault("notifications", {})
        existing = config["notifications"].get("email", {})
        settings = validate_email_notifications(payload, existing, require_credentials=True)
        subject = "[Security VM] Test Gmail alert"
        body = (
            "This is a test email from the Security VM dashboard.\n\n"
            "If you received this, Gmail notifications are configured correctly."
        )
        conn = connect(db_path)
        try:
            try:
                send_email(settings, subject, body)
                insert_notification_event(
                    conn,
                    {
                        "channel": "email",
                        "recipient": ",".join(settings["recipients"]),
                        "subject": subject,
                        "status": "sent",
                        "cooldown_key": "admin-test-email",
                    },
                )
                insert_app_event(conn, "info", "notifications", "Test Gmail notification sent")
                return {"status": "sent", "recipients": settings["recipients"]}
            except Exception as exc:
                insert_notification_event(
                    conn,
                    {
                        "channel": "email",
                        "recipient": ",".join(settings["recipients"]),
                        "subject": subject,
                        "status": "failed",
                        "error": str(exc),
                        "cooldown_key": "admin-test-email",
                    },
                )
                insert_app_event(conn, "error", "notifications", f"Test Gmail notification failed: {exc}")
                raise HTTPException(status_code=400, detail=f"Test email failed: {exc}")
        finally:
            conn.close()

    @app.post("/api/admin/firewall-blocks/{block_id}/unblock")
    def api_admin_unblock_firewall(block_id: int, payload: FirewallBlockActionRequest):
        conn = connect(db_path)
        try:
            block = get_firewall_block(conn, block_id)
            if not block:
                raise HTTPException(status_code=404, detail="Firewall block not found")
            status, elapsed_ms, rule, zone = remove_firewalld_block(
                block["ip_address"],
                block.get("direction") or "source",
                zone=block.get("zone"),
                external_zone=config.get("firewall", {}).get("external_zone", "external"),
                internal_zone=config.get("firewall", {}).get("internal_zone", "internal"),
            )
            release_firewall_block(conn, block_id, payload.analyst_name.strip() or "admin", payload.reason.strip() or status)
            insert_app_event(
                conn,
                "warning" if status.startswith("failed") else "info",
                "firewall",
                f"Unblock {block['ip_address']}: {status}",
                {"block_id": block_id, "elapsed_ms": elapsed_ms, "rule": rule, "zone": zone},
            )
            return {"status": status, "elapsed_ms": elapsed_ms}
        finally:
            conn.close()

    @app.post("/api/admin/firewall-candidates/{response_id}/enforce")
    def api_admin_enforce_firewall_candidate(response_id: int, payload: FirewallBlockActionRequest):
        conn = connect(db_path)
        try:
            candidate = get_firewall_candidate(conn, response_id)
            if not candidate:
                raise HTTPException(status_code=404, detail="Enforcement candidate not found")
            timeout = config.get("firewall", {}).get("block_timeout_seconds", 3600)
            status, elapsed_ms, rule, zone = temporary_block_firewalld(
                candidate["target_ip"],
                timeout,
                candidate.get("target_direction") or "source",
                external_zone=config.get("firewall", {}).get("external_zone", "external"),
                internal_zone=config.get("firewall", {}).get("internal_zone", "internal"),
            )
            if status == "blocked":
                insert_firewall_block(
                    conn,
                    {
                        "detection_id": candidate["detection_id"],
                        "ip_address": candidate["target_ip"],
                        "direction": candidate.get("target_direction") or "source",
                        "zone": zone,
                        "reason": payload.reason.strip() or f"Manual enforcement from response #{response_id}",
                        "firewall_rule": rule,
                        "timeout_seconds": timeout,
                        "status": "active",
                        "response_status": status,
                        "response_time_ms": elapsed_ms,
                    },
                )
            if status == "blocked":
                update_response_manual_action(
                    conn,
                    response_id,
                    "Dangerous",
                    "temporary_block",
                    "firewalld",
                    status,
                    elapsed_ms,
                )
            else:
                update_response_manual_action(
                    conn,
                    response_id,
                    "Dangerous",
                    "would_block",
                    "firewalld",
                    status,
                    elapsed_ms,
                )
            insert_app_event(
                conn,
                "warning" if status.startswith("failed") else "info",
                "firewall",
                f"Manual enforcement for {candidate['target_ip']}: {status}",
                {"response_id": response_id, "detection_id": candidate["detection_id"], "elapsed_ms": elapsed_ms, "rule": rule},
            )
            return {"status": status, "elapsed_ms": elapsed_ms}
        finally:
            conn.close()

    @app.post("/api/admin/firewall-candidates/{response_id}/mark-safe")
    def api_admin_mark_firewall_candidate_safe(response_id: int, payload: FirewallBlockActionRequest):
        duration_hours = payload.safe_duration_hours
        if duration_hours < 1 or duration_hours > 24 * 365:
            raise HTTPException(status_code=400, detail="Safe duration must be between 1 hour and 365 days")
        conn = connect(db_path)
        try:
            candidate = get_firewall_candidate(conn, response_id)
            if not candidate:
                raise HTTPException(status_code=404, detail="Enforcement candidate not found")
            add_allowlist_entry(
                conn,
                candidate["target_ip"],
                duration_hours * 60,
                name=f"Trusted after response #{response_id}",
                reason=payload.reason.strip() or "Marked safe from admin enforcement queue",
                added_by=payload.analyst_name.strip() or "admin",
            )
            update_response_manual_action(
                conn,
                response_id,
                "Authorized Activity",
                "authorized_activity",
                "none",
                "marked_safe",
                0,
            )
            insert_app_event(
                conn,
                "info",
                "firewall",
                f"Marked enforcement candidate {candidate['target_ip']} safe",
                {"response_id": response_id, "detection_id": candidate["detection_id"]},
            )
            return {"status": "safe"}
        finally:
            conn.close()

    @app.post("/api/admin/firewall-blocks/{block_id}/mark-safe")
    def api_admin_mark_firewall_block_safe(block_id: int, payload: FirewallBlockActionRequest):
        duration_hours = payload.safe_duration_hours
        if duration_hours < 1 or duration_hours > 24 * 365:
            raise HTTPException(status_code=400, detail="Safe duration must be between 1 hour and 365 days")
        conn = connect(db_path)
        try:
            block = get_firewall_block(conn, block_id)
            if not block:
                raise HTTPException(status_code=404, detail="Firewall block not found")
            status, elapsed_ms, rule, zone = remove_firewalld_block(
                block["ip_address"],
                block.get("direction") or "source",
                zone=block.get("zone"),
                external_zone=config.get("firewall", {}).get("external_zone", "external"),
                internal_zone=config.get("firewall", {}).get("internal_zone", "internal"),
            )
            add_allowlist_entry(
                conn,
                block["ip_address"],
                duration_hours * 60,
                name=f"Trusted after block #{block_id}",
                reason=payload.reason.strip() or "Marked safe from admin firewall controls",
                added_by=payload.analyst_name.strip() or "admin",
            )
            release_firewall_block(conn, block_id, payload.analyst_name.strip() or "admin", payload.reason.strip() or "marked safe")
            insert_app_event(
                conn,
                "warning" if status.startswith("failed") else "info",
                "firewall",
                f"Marked {block['ip_address']} safe after firewall block",
                {"block_id": block_id, "elapsed_ms": elapsed_ms, "rule": rule},
            )
            return {"status": "safe", "unblock_status": status, "elapsed_ms": elapsed_ms}
        finally:
            conn.close()

    @app.delete("/api/admin/trusted-ip/{ip_address}")
    def api_admin_remove_trusted_ip(ip_address: str, payload: FirewallBlockActionRequest):
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid IP address")
        conn = connect(db_path)
        try:
            removed = deactivate_allowlist_for_ip(conn, ip_address)
            if not removed:
                raise HTTPException(status_code=404, detail="No active trusted setting found for this IP")
            insert_app_event(
                conn,
                "info",
                "firewall",
                f"Removed trusted setting for {ip_address}",
                {
                    "ip_address": ip_address,
                    "removed_entries": removed,
                    "analyst_name": payload.analyst_name.strip() or "admin",
                    "reason": payload.reason.strip() or "Removed from admin incident response history",
                },
            )
            return {"status": "removed", "removed_entries": removed}
        finally:
            conn.close()

    @app.post("/api/admin/ai-model")
    def api_admin_ai_model(payload: AIModelConfigRequest):
        host, model, provider, timeout_seconds = validate_ai_model_config(payload)
        config.setdefault("ai_model", {})
        config["ai_model"]["host"] = host
        config["ai_model"]["model"] = model
        config["ai_model"]["provider"] = provider
        config["ai_model"]["timeout_seconds"] = timeout_seconds

        conn = connect(db_path)
        try:
            profile = {
                "name": f"{provider or 'ai'}:{model}",
                "host": host,
                "model": model,
                "provider": provider or "ai_service",
                "timeout_seconds": timeout_seconds,
                "status": "active",
                "notes": "Updated from AI model settings form.",
            }
            active_uid = config.get("ai_model", {}).get("active_profile_uid")
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
            if config.get("ai_model", {}).get("active_profile_uid") == profile_uid:
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

    @app.delete("/api/admin/ai-profiles/{profile_uid}")
    def api_admin_delete_ai_profile(profile_uid: str):
        conn = connect(db_path)
        try:
            profile = get_ai_profile(conn, profile_uid)
            if not profile:
                raise HTTPException(status_code=404, detail="AI profile not found")
            profiles = list_ai_profiles(conn, 100)
            if len(profiles) <= 1:
                raise HTTPException(
                    status_code=400,
                    detail="Create another AI profile before deleting the last saved profile",
                )

            selected_uid = config.get("ai_model", {}).get("active_profile_uid")
            replacement = None
            if selected_uid == profile_uid:
                replacement = next(
                    (
                        item
                        for item in profiles
                        if item["uid"] != profile_uid and item.get("status") == "active"
                    ),
                    None,
                )
                if not replacement:
                    raise HTTPException(
                        status_code=400,
                        detail="Create or activate another AI profile before deleting the selected profile",
                    )
                apply_ai_profile_to_config(config, replacement)
                mark_ai_profile_selected(conn, replacement["uid"])

            comparison_uids = [
                uid
                for uid in config.get("ai_comparison", {}).get("profile_uids", [])
                if uid != profile_uid
            ]
            config.setdefault("ai_comparison", {})["profile_uids"] = comparison_uids
            save_config(config, config_path)

            if not delete_ai_profile(conn, profile_uid):
                raise HTTPException(status_code=404, detail="AI profile not found")
            insert_app_event(
                conn,
                "info",
                "admin",
                f"Deleted AI profile {profile['name']} ({profile_uid})",
                {
                    "ai_profile_uid": profile_uid,
                    "replacement_profile_uid": replacement["uid"] if replacement else None,
                    "historical_reports_preserved": True,
                },
            )
            return {
                "status": "deleted",
                "deleted_profile_uid": profile_uid,
                "active_profile_uid": replacement["uid"] if replacement else selected_uid,
                "comparison_profile_uids": comparison_uids,
                "historical_reports_preserved": True,
            }
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

    @app.get("/api/latest-alerts")
    def api_latest_sensor_alerts(limit: int = 50, sensor: str = "all"):
        conn = connect(db_path)
        try:
            return latest_sensor_alerts(conn, limit, sensor)
        finally:
            conn.close()

    @app.get("/api/ai-opinions")
    def api_ai_opinions(limit: int = 50):
        conn = connect(db_path)
        try:
            return latest_ai_opinions(conn, limit)
        finally:
            conn.close()

    @app.get("/api/" + "olla" + "ma-reports")
    def api_legacy_ai_opinions(limit: int = 50):
        conn = connect(db_path)
        try:
            insert_app_event(
                conn,
                "warning",
                "dashboard",
                "Deprecated AI opinion API path used by a stale browser tab",
            )
            return latest_ai_opinions(conn, limit)
        finally:
            conn.close()

    @app.get("/api/ai-model-comparison")
    def api_ai_model_comparison():
        conn = connect(db_path)
        try:
            return ai_model_comparison(conn)
        finally:
            conn.close()

    @app.get("/api/ai-comparisons")
    def api_ai_comparisons(limit: int = 50, case_uid: str = None):
        conn = connect(db_path)
        try:
            return list_ai_comparison_runs(conn, max(1, min(limit, 200)), case_uid=case_uid)
        finally:
            conn.close()

    @app.get("/api/ai-comparisons/scorecard")
    def api_ai_comparison_scorecard():
        conn = connect(db_path)
        try:
            return ai_comparison_scorecard(conn)
        finally:
            conn.close()

    @app.get("/api/ai-comparisons/{comparison_uid}")
    def api_ai_comparison_detail(comparison_uid: str):
        conn = connect(db_path)
        try:
            detail = ai_comparison_detail(conn, comparison_uid)
            if not detail:
                raise HTTPException(status_code=404, detail="AI comparison not found")
            return detail
        finally:
            conn.close()

    @app.post("/api/ai-comparisons/{comparison_uid}/vote")
    def api_vote_ai_comparison(comparison_uid: str, payload: AIComparisonVoteRequest):
        conn = connect(db_path)
        try:
            try:
                saved = vote_ai_comparison(
                    conn,
                    comparison_uid,
                    payload.analyst_name.strip() or "analyst",
                    payload.selection,
                    payload.notes.strip(),
                )
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))
            if not saved:
                raise HTTPException(status_code=404, detail="AI comparison not found")
            insert_app_event(
                conn,
                "info",
                "ai_comparison",
                f"AI comparison selection recorded for {comparison_uid}",
                {"selection": payload.selection},
            )
            return ai_comparison_detail(conn, comparison_uid)
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
            active_uid = config.get("ai_model", {}).get("active_profile_uid")
            active_profile = get_ai_profile(conn, active_uid) if active_uid else None
            otx_rows = conn.execute(
                """
                SELECT
                  reputation,
                  COUNT(*) AS count,
                  SUM(COALESCE(malicious_count, 0)) AS malicious_total,
                  SUM(COALESCE(suspicious_count, 0)) AS suspicious_total
                FROM (
                  SELECT
                    indicator,
                    COALESCE(reputation, 'unknown') AS reputation,
                    MAX(COALESCE(malicious_count, 0)) AS malicious_count,
                    MAX(COALESCE(suspicious_count, 0)) AS suspicious_count
                  FROM threat_intel_lookups
                  WHERE source = 'otx'
                  GROUP BY indicator, COALESCE(reputation, 'unknown')
                )
                GROUP BY reputation
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
                (max(250, limit * 25),),
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
            encrypted_summary = encrypted_traffic_summary(conn, limit)
            zeek_counts = zeek_event_counts(conn)
            zeek_runtime = zeek_status(config)
            return {
                "timeline": detail.get("timeline", [])[-8:],
                "top_ips": detail.get("ips", [])[:limit],
                "encrypted_traffic": encrypted_summary,
                "zeek": {
                    "enabled": zeek_runtime.get("enabled"),
                    "installed": zeek_runtime.get("installed"),
                    "running": zeek_runtime.get("running"),
                    "interface": zeek_runtime.get("interface"),
                    "log_directory": zeek_runtime.get("log_directory"),
                    "event_counts": zeek_counts,
                    "logs": zeek_runtime.get("logs", []),
                    "community_packages": zeek_runtime.get("community_packages", []),
                },
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

    @app.get("/api/zeek/status")
    def api_zeek_status():
        conn = connect(db_path)
        try:
            status = zeek_status(config)
            status["event_counts"] = zeek_event_counts(conn)
            return status
        finally:
            conn.close()

    @app.get("/api/zeek/telemetry")
    def api_zeek_telemetry(limit: int = 50):
        conn = connect(db_path)
        try:
            summary = zeek_telemetry_summary(conn, limit)
            summary["runtime"] = zeek_status(config)
            return summary
        finally:
            conn.close()

    @app.get("/api/zeek/events")
    def api_zeek_events(limit: int = 50, log_type: str = None):
        conn = connect(db_path)
        try:
            return latest_zeek_events(conn, limit, log_type)
        finally:
            conn.close()

    @app.get("/api/zeek/events/{event_id}")
    def api_zeek_event(event_id: int):
        conn = connect(db_path)
        try:
            row = conn.execute("SELECT * FROM zeek_events WHERE id = ?", (event_id,)).fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Zeek event not found")
            return dict(row)
        finally:
            conn.close()

    @app.get("/api/detections/{detection_id}/zeek-context")
    def api_detection_zeek_context(detection_id: int, seconds: int = 120):
        seconds = max(1, min(seconds, 600))
        conn = connect(db_path)
        try:
            return zeek_context_for_detection(conn, detection_id, seconds=seconds)
        finally:
            conn.close()

    @app.post("/api/detections/{detection_id}/investigation")
    def api_create_investigation(detection_id: int, payload: InvestigationRequest):
        conn = connect(db_path)
        try:
            try:
                evidence = create_incident_evidence(
                    conn,
                    config,
                    detection_id,
                    seconds_before=payload.seconds_before,
                    seconds_after=payload.seconds_after,
                    ip_filter_enabled=payload.ip_filter_enabled,
                )
                insert_app_event(
                    conn,
                    "info",
                    "incident_evidence",
                    f"Created incident evidence for detection {detection_id}",
                    {"incident_evidence_id": evidence.get("id"), "status": evidence.get("status")},
                )
                return {"status": "created", "incident_evidence": evidence}
            except ValueError as exc:
                insert_app_event(conn, "error", "incident_evidence", str(exc), {"detection_id": detection_id})
                raise HTTPException(status_code=400, detail=str(exc))
        finally:
            conn.close()

    @app.get("/api/detections/{detection_id}/incident-evidence")
    def api_detection_incident_evidence(detection_id: int):
        conn = connect(db_path)
        try:
            rows = conn.execute(
                "SELECT * FROM incident_evidence WHERE detection_id = ? ORDER BY id DESC",
                (detection_id,),
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    @app.get("/api/incident-evidence/{evidence_id}")
    def api_incident_evidence(evidence_id: int):
        conn = connect(db_path)
        try:
            row = conn.execute("SELECT * FROM incident_evidence WHERE id = ?", (evidence_id,)).fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Incident evidence not found")
            return dict(row)
        finally:
            conn.close()

    def stored_json_file(evidence_id, column):
        conn = connect(db_path)
        try:
            row = conn.execute("SELECT * FROM incident_evidence WHERE id = ?", (evidence_id,)).fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Incident evidence not found")
            path = row[column]
            if not path:
                raise HTTPException(status_code=404, detail=f"{column} is not available for this evidence")
            try:
                return json.loads(Path(path).read_text(encoding="utf-8"))
            except OSError as exc:
                raise HTTPException(status_code=404, detail=f"Evidence file unavailable: {exc}")
            except json.JSONDecodeError as exc:
                raise HTTPException(status_code=500, detail=f"Evidence file is not valid JSON: {exc}")
        finally:
            conn.close()

    @app.get("/api/incident-evidence/{evidence_id}/manifest")
    def api_incident_manifest(evidence_id: int):
        return stored_json_file(evidence_id, "evidence_manifest_path")

    @app.get("/api/incident-evidence/{evidence_id}/zeek/events")
    def api_incident_zeek_events(evidence_id: int):
        return stored_json_file(evidence_id, "zeek_logs_path")

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
                    error = redact_secrets(exc, config)
                    insert_app_event(conn, "error", "enrichment", f"OTX lookup failed for {ip_address}: {error}")
                    results.append({"ip_address": ip_address, "status": "error", "error": error})
                except Exception as exc:
                    error = redact_secrets(exc, config)
                    insert_app_event(conn, "error", "enrichment", f"OTX lookup failed for {ip_address}: {error}")
                    results.append({"ip_address": ip_address, "status": "error", "error": error})
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
                error = redact_secrets(exc, config)
                insert_app_event(conn, "error", "enrichment", f"OTX API connection test failed: {error}")
                return {"ok": False, "status": "failed", "error": error}
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
        if outcome and outcome not in {"safe", "human_review", "high_risk", "dangerous"}:
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
            zeek_context = zeek_context_for_detection(conn, detection_id, seconds=120)
            runtime_config = load_config(config_path)
            detail["src_threat_intel"] = provider_evidence_for_indicator(
                conn, runtime_config, detail.get("src_ip")
            )
            detail["dest_threat_intel"] = provider_evidence_for_indicator(
                conn, runtime_config, detail.get("dest_ip")
            )
        finally:
            conn.close()
        detail["zeek_context"] = zeek_context
        return detail

    @app.get("/api/cases/{case_uid}")
    def api_case_workspace(case_uid: str):
        conn = connect(db_path)
        try:
            detail = case_workspace(conn, case_uid)
            if not detail:
                raise HTTPException(status_code=404, detail="Case not found")
            runtime_config = load_config(config_path)
            detail["src_threat_intel"] = provider_evidence_for_indicator(
                conn, runtime_config, detail.get("src_ip")
            )
            detail["dest_threat_intel"] = provider_evidence_for_indicator(
                conn, runtime_config, detail.get("dest_ip")
            )
            return detail
        finally:
            conn.close()

    @app.post("/api/cases/{case_uid}/reassess")
    def api_reassess_case(case_uid: str):
        conn = connect(db_path)
        try:
            return reassess_case(conn, load_config(config_path), case_uid)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except requests.RequestException as exc:
            insert_app_event(
                conn,
                "error",
                "reassessment",
                f"AI reassessment failed for case {case_uid}: {type(exc).__name__}",
            )
            raise HTTPException(status_code=502, detail="AI model reassessment failed")
        finally:
            conn.close()

    @app.get("/api/cases/{case_uid}/ai-comparisons")
    def api_case_ai_comparisons(case_uid: str, limit: int = 20):
        conn = connect(db_path)
        try:
            return list_ai_comparison_runs(conn, max(1, min(limit, 100)), case_uid=case_uid)
        finally:
            conn.close()

    @app.post("/api/cases/{case_uid}/ai-comparison")
    def api_run_case_ai_comparison(case_uid: str):
        conn = connect(db_path)
        try:
            return run_model_comparison(conn, load_config(config_path), case_uid)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        finally:
            conn.close()

    @app.post("/api/cases/{case_uid}/virustotal/refresh")
    def api_refresh_case_virustotal(case_uid: str):
        conn = connect(db_path)
        try:
            return {
                "case_uid": case_uid,
                "results": refresh_case_virustotal(conn, load_config(config_path), case_uid),
            }
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        finally:
            conn.close()

    @app.get("/api/ip-detail")
    def api_ip_detail(address: str, limit: int = 100):
        conn = connect(db_path)
        try:
            detail = ip_detail(conn, address, limit)
            detail["threat_intel"] = provider_evidence_for_indicator(
                conn, load_config(config_path), detail.get("ip_address")
            )
            return detail
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid IP address")
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

    @app.post("/api/admin/assets")
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
        if action not in {"confirm", "log_only", "human_review", "investigate", "escalate"}:
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

    @app.get("/api/ai-status")
    def api_ai_status():
        conn = connect(db_path)
        try:
            try:
                status = check_ai_model(config)
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
                return {"ok": False, "error": str(exc), "host": config.get("ai_model", {}).get("host")}
        finally:
            conn.close()

    @app.get("/api/" + "olla" + "ma-status")
    def api_legacy_ai_status():
        return api_ai_status()

    @app.get("/api/metrics")
    def api_metrics():
        conn = connect(db_path)
        try:
            suricata_alerts = conn.execute("SELECT COUNT(*) AS count FROM alerts").fetchone()["count"]
            zeek_detection_findings = conn.execute(
                "SELECT COUNT(*) AS count FROM sensor_findings WHERE sensor = 'zeek' AND finding_type = 'notice'"
            ).fetchone()["count"]
            total_alerts = suricata_alerts + zeek_detection_findings
            total_detections = conn.execute("SELECT COUNT(*) AS count FROM detections").fetchone()["count"]
            total_assets = conn.execute("SELECT COUNT(*) AS count FROM assets WHERE status = 'active'").fetchone()["count"]
            zeek_counts = zeek_event_counts(conn)
            zeek_notice_count = zeek_counts.get("notice", 0)
            zeek_weird_count = zeek_counts.get("weird", 0)
            investigation_cases = total_detections
            ai_reassessments = conn.execute(
                "SELECT COUNT(*) AS count FROM ai_assessments WHERE assessment_type = 'reassessment'"
            ).fetchone()["count"]
            by_type = conn.execute(
                "SELECT detection_type, COUNT(*) AS count FROM detections GROUP BY detection_type ORDER BY count DESC"
            ).fetchall()
            by_classification = conn.execute(
                """
                SELECT final_classification, final_action, COUNT(*) AS count
                FROM responses
                WHERE id = (
                  SELECT MAX(r2.id) FROM responses r2 WHERE r2.detection_id = responses.detection_id
                )
                GROUP BY final_classification, final_action
                """
            ).fetchall()
            outcome_counts = {
                "safe": 0,
                "human_review": 0,
                "high_risk": 0,
                "dangerous": 0,
            }
            for row in by_classification:
                classification = str(row["final_classification"] or "").lower()
                action = str(row["final_action"] or "").lower()
                count = row["count"]
                if classification == "dangerous":
                    outcome_counts["dangerous"] += count
                elif "high risk" in classification:
                    outcome_counts["high_risk"] += count
                elif "human" in classification:
                    outcome_counts["human_review"] += count
                else:
                    outcome_counts["safe"] += count
            return {
                "total_alerts": total_alerts,
                "total_detections": total_detections,
                "total_assets": total_assets,
                "zeek_notice_count": zeek_notice_count,
                "zeek_weird_count": zeek_weird_count,
                "zeek_event_counts": zeek_counts,
                "multi_sensor_detections": conn.execute(
                    "SELECT COUNT(*) AS count FROM detections WHERE sensor_state = 'multi_sensor'"
                ).fetchone()["count"],
                "investigations_ready": investigation_cases,
                "investigations_failed": 0,
                "ai_reassessments": ai_reassessments,
                "outcome_counts": outcome_counts,
                "detections_by_type": [dict(row) for row in by_type],
                "mode": config.get("system", {}).get("mode"),
            }
        finally:
            conn.close()

    return app

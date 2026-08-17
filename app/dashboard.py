"""Connect the browser interface to stored application data through FastAPI.

``create_app`` receives a config path and returns the FastAPI application run by
Uvicorn. Page routes serve HTML from ``static/``. API routes open the configured
SQLite database, call query/helper functions, and return JSON that the matching
JavaScript file renders in the browser. Write routes handle explicit operator
actions such as feedback, settings changes, comparison requests, or cancellation.

The HTML/JavaScript frontend is intentionally a view over SQLite rather than an
analysis engine. Refreshing a page rereads stored data but does not ingest sensor
files or run AI analysis; those tasks remain in background workers. Facts labelled
as Python come from normalized fields, while AI text comes from stored reports.
"""

from pathlib import Path
import base64
import binascii
import csv
import io
import importlib.util
import json
import os
import secrets
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from typing import Dict, List, Optional
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
import requests
from pydantic import BaseModel

from app.config import load_config, save_config
from app.database import (
    ai_model_comparison,
    ai_comparison_detail,
    cancel_ai_request,
    cancel_all_ai_requests,
    ai_comparison_candidate_export_rows,
    ai_comparison_selection_summary,
    ai_experiment_detail,
    ai_experiment_export_rows,
    case_workspace,
    connect,
    create_ai_profile,
    delete_ai_profile,
    ensure_ai_profile_from_config,
    get_ai_profile,
    init_db,
    insert_app_event,
    investigation_detail,
    latest_ai_request_activity,
    latest_runtime_components,
    latest_sensor_alerts,
    latest_app_events,
    latest_decision_evidence,
    latest_zeek_events,
    list_ai_profiles,
    list_ai_comparison_runs,
    list_ai_experiment_runs,
    list_review_queue,
    mark_ai_profile_selected,
    public_ips_for_enrichment,
    promote_ai_comparison_winner,
    reset_dashboard_logs,
    set_ai_worker_paused,
    reopen_ai_comparison_review,
    review_ai_experiment_result,
    submit_analyst_review,
    upsert_threat_intel_lookup,
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
    zeek_context_threat_intel,
)
from app.ai_client import check_ai_model, model_metadata
from app.ai_comparison import (
    queue_missing_evidence_experiment,
    queue_model_comparison,
    queue_stability_experiment,
)
from app.case_assessment import reassess_case, refresh_case_virustotal
from app.security import redact_secrets
from app.zeek_inventory import zeek_status


STATIC_DIR = Path(__file__).resolve().parents[1] / "static"
NO_CACHE_HEADERS = {"Cache-Control": "no-store, max-age=0"}


def static_page(filename):
    """Return a handler that serves one static dashboard page."""
    return FileResponse(STATIC_DIR / filename, headers=NO_CACHE_HEADERS)


class AnalystReviewRequest(BaseModel):
    """Validate an analyst's explicit decision and optional case notes."""

    action: str
    analyst_name: str = ""
    notes: str = ""
    classification: str = None
    tuning_label: str = ""


class AIModelConfigRequest(BaseModel):
    """Validate connection settings for one Ollama-compatible model endpoint."""

    host: str
    model: str
    provider: str = ""
    timeout_seconds: int = 90


class AIProfileRequest(AIModelConfigRequest):
    """Describe a reusable model profile without exposing its runtime output."""

    name: str
    status: str = "active"
    notes: str = ""


class AIComparisonSettingsRequest(BaseModel):
    """Select which saved model profiles participate in future comparisons."""

    profile_uids: List[str]


class AIComparisonVoteRequest(BaseModel):
    """Record a blind response selection or reject-all comparison decision."""

    analyst_name: str = "analyst"
    selection: str
    notes: str = ""


class AIComparisonQueueRequest(BaseModel):
    """Optionally choose profiles when adding a case to the durable queue."""

    profile_uids: List[str] = []


class StabilitySettingRequest(BaseModel):
    """Define one controlled temperature-and-seed experiment variation."""

    label: str = ""
    temperature: float
    seed: int


class StabilityExperimentRequest(BaseModel):
    """Run configured generation variations against one frozen comparison."""

    comparison_uid: str
    settings: List[StabilitySettingRequest]


class MissingEvidenceVariantRequest(BaseModel):
    """Name one experiment variation and the evidence sections it removes."""

    label: str = ""
    mask: List[str]


class MissingEvidenceExperimentRequest(BaseModel):
    """Run evidence-removal variants against one reviewed comparison input."""

    comparison_uid: str
    variants: List[MissingEvidenceVariantRequest]


class AIExperimentReviewRequest(BaseModel):
    """Capture manual quality ratings without changing operational decisions."""

    grounding_score: Optional[int] = None
    completeness_score: Optional[int] = None
    next_step_quality_score: Optional[int] = None
    uncertainty_score: Optional[int] = None
    usefulness_score: Optional[int] = None
    supported_claims: Optional[int] = None
    unsupported_claims: Optional[int] = None
    contradicted_claims: Optional[int] = None
    undecidable_claims: Optional[int] = None
    missing_evidence_acknowledged: bool = False
    reviewer_name: str = "analyst"
    reviewer_notes: str = ""


class AIComparisonPromotionRequest(BaseModel):
    """Identify the analyst promoting a selected response to the case view."""

    analyst_name: str = "analyst"
    notes: str = ""


class ResetLogsRequest(BaseModel):
    """Require an explicit confirmation phrase before deleting operational rows."""

    confirm: str


class ThreatIntelProviderRequest(BaseModel):
    """Validate enablement, credential, and refresh settings for one provider."""

    enabled: bool = False
    api_key: str = ""
    refresh_hours: int = 24


class ThreatIntelAdminRequest(BaseModel):
    """Update the configured threat-intelligence providers as one operation."""

    providers: Dict[str, ThreatIntelProviderRequest]


class OtxLookupRequest(BaseModel):
    """Limit and scope a manual OTX lookup initiated from the dashboard."""

    limit: int = 5
    scope: str = "top5"
    detection_type: Optional[str] = None


class OtxStatusRequest(BaseModel):
    """Supply an optional OTX key for a connection test without returning it."""

    otx_api_key: str = ""


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

def tool_status():
    """Return normalized tool status information for the Admin page."""
    tools = []
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
                "fix_command": "",
                "after_fix": "",
            }
        )
    return tools


def tool_version(path):
    """Return normalized tool version information for the Admin page."""
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
    """Return normalized python package status information for the Admin page."""
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


def validate_ai_model_config(payload):
    """Check that the AI model settings are valid."""
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
    """Check that the AI profile settings are valid."""
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
    """Copy a selected stored AI profile into the active YAML configuration."""
    config.setdefault("ai_model", {})
    config["ai_model"]["active_profile_uid"] = profile["uid"]
    config["ai_model"]["host"] = profile["host"]
    config["ai_model"]["model"] = profile["model"]
    config["ai_model"]["provider"] = profile["provider"]
    config["ai_model"]["timeout_seconds"] = int(profile.get("timeout_seconds") or 90)


def create_app(config_path):
    """Create the FastAPI application bound to one YAML/SQLite configuration.

    Endpoints open short-lived database connections per request. Secrets are
    masked before settings or errors are serialized to dashboard clients.
    """
    config = load_config(config_path)
    db_path = config.get("database", {}).get("path", "security_vm.db")
    admin_username = os.environ.get("SECURITY_VM_ADMIN_USER", "admin")
    admin_password = os.environ.get("SECURITY_VM_ADMIN_PASSWORD", "")
    init_db(db_path).close()
    app = FastAPI(title="Security VM Dashboard")
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.middleware("http")
    async def add_no_cache_headers(request, call_next):
        """Disable browser caching and protect administrative routes."""
        path = request.url.path
        admin_only = (
            path in {"/admin", "/compare"}
            or path.startswith(
                (
                    "/api/admin/",
                    "/api/ai-comparisons",
                    "/api/ai-experiments",
                    "/api/ai-experiment-results",
                    "/experiments/",
                )
            )
            or (
                path.startswith("/api/cases/")
                and path.endswith(("/ai-comparisons", "/ai-comparison"))
            )
        )
        if admin_only:
            if not admin_password:
                return JSONResponse(
                    status_code=503,
                    content={
                        "detail": (
                            "Admin access is disabled. Set SECURITY_VM_ADMIN_PASSWORD "
                            "before starting Security VM."
                        )
                    },
                )
            authorization = request.headers.get("Authorization", "")
            authenticated = False
            if authorization.startswith("Basic "):
                try:
                    decoded = base64.b64decode(
                        authorization.split(" ", 1)[1],
                        validate=True,
                    ).decode("utf-8")
                    supplied_username, supplied_password = decoded.split(":", 1)
                    authenticated = (
                        secrets.compare_digest(supplied_username, admin_username)
                        and secrets.compare_digest(supplied_password, admin_password)
                    )
                except (binascii.Error, ValueError, UnicodeDecodeError):
                    authenticated = False
            if not authenticated:
                return Response(
                    status_code=401,
                    content="Admin authentication required",
                    headers={"WWW-Authenticate": 'Basic realm="Security VM Admin"'},
                    media_type="text/plain",
                )
        response = await call_next(request)
        if request.url.path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-store, max-age=0"
        return response

    @app.get("/")
    def index():
        """Serve the main Security VM dashboard page."""
        return static_page("index.html")

    @app.get("/outcome")
    def outcome_workbook():
        """Serve the classification-outcome workbook page."""
        return static_page("outcome.html")

    @app.get("/investigation")
    def investigation_workbook():
        """Serve the detailed case investigation page."""
        return static_page("investigation.html")

    @app.get("/compare")
    def ai_comparison_workbook():
        """Open the AI comparison page."""
        return static_page("compare.html")

    @app.get("/experiments/stability")
    @app.get("/experiments/missing-evidence")
    def ai_experiment_workbook():
        """Open the AI experiments page."""
        return static_page("experiments.html")

    @app.get("/zeek")
    def zeek_telemetry_workbook():
        """Open the Zeek telemetry page."""
        return static_page("zeek.html")

    @app.get("/admin")
    def admin_controls():
        """Serve the authenticated administration controls page."""
        return static_page("admin.html")

    @app.get("/api/admin/settings")
    def api_admin_settings(limit: int = 500):
        """Serve the admin settings API endpoint."""
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
                    "candidate_count": len(
                        config.get("ai_comparison", {}).get("profile_uids", [])
                    ),
                    "sequential": True,
                },
                "network": {
                    "internal_interface": config.get("assets", {}).get("internal_interface", "ens37"),
                    "suricata_eve_json_path": config.get("suricata", {}).get("eve_json_path", ""),
                    "zeek_interface": config.get("zeek", {}).get("interface", ""),
                    "zeek_log_directory": config.get("zeek", {}).get("log_directory", ""),
                },
                "host_os": zeek_os_recommendation(detect_os_release()),
                "threat_intel": {
                    "providers": sanitized_provider_status(config, conn),
                },
                "tools": tool_status(),
                "python_packages": python_package_status(),
            }
        finally:
            conn.close()

    @app.get("/api/admin/runtime-console")
    def api_admin_runtime_console(limit: int = 100):
        """Return sanitized request lifecycles and background component events."""
        conn = connect(db_path)
        try:
            activities = latest_ai_request_activity(conn, max(1, min(limit, 200)))
            events = latest_app_events(conn, max(1, min(limit, 200)))
            for event in events:
                event["details"] = redact_secrets(event.get("details") or "", config)
            return {
                "active_requests": sum(
                    1 for activity in activities if activity.get("status") == "active"
                ),
                "components": latest_runtime_components(conn),
                "ai_requests": activities,
                "events": events,
                "ai_worker_paused": bool(
                    conn.execute("SELECT paused FROM ai_worker_control WHERE id = 1").fetchone()["paused"]
                ),
            }
        finally:
            conn.close()

    @app.post("/api/admin/ai-requests/{activity_uid}/cancel")
    def api_cancel_ai_request(activity_uid: str):
        """Serve the cancel AI request API endpoint."""
        conn = connect(db_path)
        try:
            if not cancel_ai_request(conn, activity_uid):
                raise HTTPException(status_code=404, detail="Active AI request not found")
            return {"ok": True, "activity_uid": activity_uid}
        finally:
            conn.close()

    @app.post("/api/admin/ai-requests/cancel-all")
    def api_cancel_all_ai_requests():
        """Serve the cancel all AI requests API endpoint."""
        conn = connect(db_path)
        try:
            return {"ok": True, "cancelled": cancel_all_ai_requests(conn), "paused": True}
        finally:
            conn.close()

    @app.post("/api/admin/ai-worker/resume")
    def api_resume_ai_worker():
        """Serve the resume AI worker API endpoint."""
        conn = connect(db_path)
        try:
            set_ai_worker_paused(conn, False)
            return {"ok": True, "paused": False}
        finally:
            conn.close()

    @app.put("/api/admin/threat-intel")
    def api_admin_threat_intel(payload: ThreatIntelAdminRequest):
        """Serve the admin threat intel API endpoint."""
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
        """Serve the admin AI comparison API endpoint."""
        profile_uids = list(dict.fromkeys(uid.strip() for uid in payload.profile_uids if uid.strip()))
        if not profile_uids:
            raise HTTPException(status_code=400, detail="Select at least one active AI profile")
        conn = connect(db_path)
        try:
            for uid in profile_uids:
                profile = get_ai_profile(conn, uid)
                if not profile:
                    raise HTTPException(status_code=404, detail=f"AI profile {uid} was not found")
                if profile.get("status") != "active":
                    raise HTTPException(status_code=400, detail=f"AI profile {uid} is inactive")
            config.setdefault("ai_comparison", {})["profile_uids"] = profile_uids
            config["ai_comparison"]["candidate_count"] = len(profile_uids)
            config["ai_comparison"]["sequential"] = True
            save_config(config, config_path)
            insert_app_event(
                conn,
                "info",
                "ai_comparison",
                "Updated AI comparison profiles",
                {"profile_count": len(profile_uids), "sequential": True},
            )
            return {"status": "saved", "profile_uids": profile_uids, "sequential": True}
        finally:
            conn.close()

    @app.post("/api/admin/threat-intel/{source}/refresh")
    def api_admin_refresh_threat_intel(source: str):
        """Serve the admin refresh threat intel API endpoint."""
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
        """Serve the admin refresh active threat intel API endpoint."""
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

    @app.post("/api/admin/ai-model")
    def api_admin_ai_model(payload: AIModelConfigRequest):
        """Serve the admin AI model API endpoint."""
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
        """Serve the admin create AI profile API endpoint."""
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
        """Serve the admin update AI profile API endpoint."""
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
        """Serve the admin select AI profile API endpoint."""
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
        """Serve the admin delete AI profile API endpoint."""
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

    @app.get("/api/latest-alerts")
    def api_latest_decision_evidence(limit: int = 50, sensor: str = "all"):
        """Serve the latest sensor alerts API endpoint."""
        conn = connect(db_path)
        try:
            return latest_sensor_alerts(conn, limit, sensor)
        finally:
            conn.close()

    @app.get("/api/ai-comparisons")
    def api_ai_comparisons(limit: int = 50, case_uid: str = None):
        """Serve the AI comparisons API endpoint."""
        conn = connect(db_path)
        try:
            return list_ai_comparison_runs(conn, max(1, min(limit, 200)), case_uid=case_uid)
        finally:
            conn.close()

    @app.get("/api/ai-comparisons/options")
    def api_ai_comparison_options(limit: int = 200):
        """Serve the AI comparison options API endpoint."""
        conn = connect(db_path)
        try:
            cases = conn.execute(
                """
                SELECT case_uid, detection_type, first_seen AS timestamp,
                       src_ip, dest_ip,
                       COALESCE((
                         SELECT finding_name FROM sensor_findings
                         WHERE detection_id = detections.id
                         ORDER BY id LIMIT 1
                       ), detection_type) AS signature
                FROM detections
                WHERE case_uid IS NOT NULL
                ORDER BY id DESC LIMIT ?
                """,
                (max(1, min(limit, 1000)),),
            ).fetchall()
            return {
                "cases": [dict(row) for row in cases],
                "profiles": [
                    profile
                    for profile in list_ai_profiles(conn, 500)
                    if profile.get("status") == "active"
                ],
            }
        finally:
            conn.close()

    @app.get("/api/ai-comparisons/selection-summary")
    def api_ai_comparison_selection_summary():
        """Serve the AI comparison selection summary API endpoint."""
        conn = connect(db_path)
        try:
            return ai_comparison_selection_summary(conn)
        finally:
            conn.close()

    @app.get("/api/ai-comparisons/export")
    def api_ai_comparison_export(format: str = "csv"):
        """Serve the AI comparison export API endpoint."""
        conn = connect(db_path)
        try:
            rows = ai_comparison_candidate_export_rows(conn)
        finally:
            conn.close()
        if format.lower() == "json":
            content = json.dumps(
                {
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "record_count": len(rows),
                    "candidates": rows,
                },
                indent=2,
                default=str,
            )
            return Response(
                content=content,
                media_type="application/json",
                headers={
                    "Content-Disposition": 'attachment; filename="ai-comparison-results.json"'
                },
            )
        if format.lower() != "csv":
            raise HTTPException(status_code=400, detail="format must be csv or json")
        fieldnames = []
        for row in rows:
            for key in row:
                if key not in fieldnames:
                    fieldnames.append(key)
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=fieldnames or ["comparison_uid"])
        writer.writeheader()
        writer.writerows(rows)
        return Response(
            content=output.getvalue(),
            media_type="text/csv",
            headers={
                "Content-Disposition": 'attachment; filename="ai-comparison-results.csv"'
            },
        )

    @app.get("/api/ai-experiments")
    def api_ai_experiments(
        limit: int = 100,
        experiment_type: Optional[str] = None,
    ):
        """Serve the AI experiments API endpoint."""
        conn = connect(db_path)
        try:
            return list_ai_experiment_runs(
                conn,
                experiment_type=experiment_type,
                limit=max(1, min(limit, 500)),
            )
        finally:
            conn.close()

    @app.get("/api/ai-experiments/export")
    def api_ai_experiment_export(
        format: str = "csv",
        experiment_type: Optional[str] = None,
    ):
        """Serve the AI experiment export API endpoint."""
        conn = connect(db_path)
        try:
            rows = ai_experiment_export_rows(conn, experiment_type)
        finally:
            conn.close()
        if format.lower() == "json":
            return Response(
                content=json.dumps(
                    {
                        "generated_at": datetime.now(timezone.utc).isoformat(),
                        "record_count": len(rows),
                        "experiment_type": experiment_type,
                        "results": rows,
                    },
                    indent=2,
                    default=str,
                ),
                media_type="application/json",
                headers={
                    "Content-Disposition": 'attachment; filename="llm-experiment-results.json"'
                },
            )
        if format.lower() != "csv":
            raise HTTPException(status_code=400, detail="format must be csv or json")
        fieldnames = []
        for row in rows:
            for key in row:
                if key not in fieldnames:
                    fieldnames.append(key)
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=fieldnames or ["experiment_uid"])
        writer.writeheader()
        writer.writerows(rows)
        return Response(
            content=output.getvalue(),
            media_type="text/csv",
            headers={
                "Content-Disposition": 'attachment; filename="llm-experiment-results.csv"'
            },
        )

    @app.get("/api/ai-experiments/{experiment_uid}")
    def api_ai_experiment_detail(experiment_uid: str):
        """Serve the AI experiment detail API endpoint."""
        conn = connect(db_path)
        try:
            detail = ai_experiment_detail(conn, experiment_uid)
            if not detail:
                raise HTTPException(status_code=404, detail="Experiment not found")
            return detail
        finally:
            conn.close()

    @app.post("/api/ai-experiment-results/{result_uid}/review")
    def api_review_ai_experiment_result(
        result_uid: str,
        payload: AIExperimentReviewRequest,
    ):
        """Serve the review AI experiment result API endpoint."""
        conn = connect(db_path)
        try:
            review = payload.model_dump() if hasattr(payload, "model_dump") else payload.dict()
            try:
                saved = review_ai_experiment_result(conn, result_uid, review)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))
            if not saved:
                raise HTTPException(status_code=404, detail="Experiment result not found")
            return {"result_uid": result_uid, "status": "reviewed"}
        finally:
            conn.close()

    @app.post("/api/ai-experiments/stability", status_code=202)
    def api_queue_stability_experiment(payload: StabilityExperimentRequest):
        """Serve the queue stability experiment API endpoint."""
        conn = connect(db_path)
        try:
            settings = [
                item.model_dump() if hasattr(item, "model_dump") else item.dict()
                for item in payload.settings
            ]
            experiment_uid = queue_stability_experiment(
                conn,
                payload.comparison_uid,
                settings,
            )
            return {"experiment_uid": experiment_uid, "status": "queued"}
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        finally:
            conn.close()

    @app.post("/api/ai-experiments/missing-evidence", status_code=202)
    def api_queue_missing_evidence_experiment(
        payload: MissingEvidenceExperimentRequest,
    ):
        """Serve the queue missing evidence experiment API endpoint."""
        conn = connect(db_path)
        try:
            variants = [
                item.model_dump() if hasattr(item, "model_dump") else item.dict()
                for item in payload.variants
            ]
            experiment_uid = queue_missing_evidence_experiment(
                conn,
                payload.comparison_uid,
                variants,
            )
            return {"experiment_uid": experiment_uid, "status": "queued"}
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        finally:
            conn.close()

    @app.get("/api/ai-comparisons/{comparison_uid}")
    def api_ai_comparison_detail(comparison_uid: str):
        """Serve the AI comparison detail API endpoint."""
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
        """Serve the vote AI comparison API endpoint."""
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

    @app.post("/api/ai-comparisons/{comparison_uid}/reopen")
    def api_reopen_ai_comparison(comparison_uid: str):
        """Serve the reopen AI comparison API endpoint."""
        conn = connect(db_path)
        try:
            try:
                reopened = reopen_ai_comparison_review(conn, comparison_uid)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))
            if not reopened:
                raise HTTPException(status_code=404, detail="AI comparison not found")
            insert_app_event(
                conn,
                "info",
                "ai_comparison",
                f"AI comparison review reopened for {comparison_uid}",
                {"comparison_uid": comparison_uid},
            )
            return ai_comparison_detail(conn, comparison_uid)
        finally:
            conn.close()

    @app.post("/api/ai-comparisons/{comparison_uid}/use-as-case-explanation")
    def api_use_ai_comparison_as_case_explanation(
        comparison_uid: str,
        payload: AIComparisonPromotionRequest,
    ):
        """Serve the use AI comparison as case explanation API endpoint."""
        conn = connect(db_path)
        try:
            try:
                promoted = promote_ai_comparison_winner(
                    conn,
                    comparison_uid,
                    payload.analyst_name.strip() or "analyst",
                    payload.notes.strip(),
                )
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))
            if not promoted:
                raise HTTPException(status_code=404, detail="AI comparison not found")
            insert_app_event(
                conn,
                "info",
                "ai_comparison",
                f"Selected AI comparison response promoted for {comparison_uid}",
                {"comparison_uid": comparison_uid},
            )
            return ai_comparison_detail(conn, comparison_uid)
        finally:
            conn.close()

    @app.get("/api/dashboard-summary")
    def api_dashboard_summary(limit: int = 12):
        """Return the compact timeline and Zeek data shown on the homepage."""
        conn = connect(db_path)
        try:
            timeline_rows = conn.execute(
                """
                SELECT
                  substr(COALESCE(first_seen, created_at), 1, 13) AS bucket,
                  COUNT(*) AS count
                FROM detections
                GROUP BY bucket
                ORDER BY bucket DESC
                LIMIT ?
                """,
                (max(1, min(int(limit), 100)),),
            ).fetchall()
            comparison = ai_model_comparison(conn)
            active_uid = config.get("ai_model", {}).get("active_profile_uid")
            active_profile = get_ai_profile(conn, active_uid) if active_uid else None
            zeek_counts = zeek_event_counts(conn)
            zeek_runtime = zeek_status(config)
            return {
                "timeline": [dict(row) for row in reversed(timeline_rows)],
                "model_comparison": comparison,
                "active_ai_profile": active_profile,
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
            }
        finally:
            conn.close()

    @app.get("/api/zeek/status")
    def api_zeek_status():
        """Serve the Zeek status API endpoint."""
        conn = connect(db_path)
        try:
            status = zeek_status(config)
            status["event_counts"] = zeek_event_counts(conn)
            return status
        finally:
            conn.close()

    @app.get("/api/zeek/telemetry")
    def api_zeek_telemetry(limit: int = 50):
        """Serve the Zeek telemetry API endpoint."""
        conn = connect(db_path)
        try:
            summary = zeek_telemetry_summary(conn, limit)
            summary["runtime"] = zeek_status(config)
            return summary
        finally:
            conn.close()

    @app.get("/api/zeek/events")
    def api_zeek_events(limit: int = 50, log_type: str = None):
        """Serve the Zeek events API endpoint."""
        conn = connect(db_path)
        try:
            return latest_zeek_events(conn, limit, log_type)
        finally:
            conn.close()

    @app.get("/api/zeek/events/{event_id}")
    def api_zeek_event(event_id: int):
        """Serve the Zeek event API endpoint."""
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
        """Serve the detection Zeek context API endpoint."""
        seconds = max(1, min(seconds, 600))
        conn = connect(db_path)
        try:
            return zeek_context_for_detection(conn, detection_id, seconds=seconds)
        finally:
            conn.close()

    @app.post("/api/otx-lookups")
    def api_otx_lookups(payload: OtxLookupRequest):
        """Serve the OTX lookups API endpoint."""
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
        """Serve the OTX status API endpoint."""
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

    @app.get("/api/decision-evidence")
    def api_decision_evidence(limit: int = 25, detection_type: str = None, outcome: str = None):
        """Serve the decision evidence API endpoint."""
        if outcome and outcome not in {"safe", "human_review", "dangerous"}:
            raise HTTPException(status_code=400, detail="Unsupported outcome filter")
        conn = connect(db_path)
        try:
            return latest_decision_evidence(conn, limit, detection_type, outcome)
        finally:
            conn.close()

    @app.get("/api/investigation/{detection_id}")
    def api_investigation(detection_id: int):
        """Serve the investigation API endpoint."""
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
        """Serve the case workspace API endpoint."""
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
            detail["zeek_threat_intel"] = zeek_context_threat_intel(
                conn,
                runtime_config,
                (detail.get("zeek_context") or {}).get("items") or [],
                limit=50,
                provenance_limit=4,
            )
            return detail
        finally:
            conn.close()

    @app.post("/api/cases/{case_uid}/reassess")
    def api_reassess_case(case_uid: str):
        """Rerun one stored case with current config.yaml AI settings."""
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
        """Serve the case AI comparisons API endpoint."""
        conn = connect(db_path)
        try:
            return list_ai_comparison_runs(conn, max(1, min(limit, 100)), case_uid=case_uid)
        finally:
            conn.close()

    @app.post("/api/cases/{case_uid}/ai-comparison", status_code=202)
    def api_run_case_ai_comparison(
        case_uid: str,
        payload: Optional[AIComparisonQueueRequest] = None,
    ):
        """Serve the run case AI comparison API endpoint."""
        conn = connect(db_path)
        try:
            return queue_model_comparison(
                conn,
                load_config(config_path),
                case_uid,
                (payload.profile_uids if payload else None),
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        finally:
            conn.close()

    @app.post("/api/cases/{case_uid}/virustotal/refresh")
    def api_refresh_case_virustotal(case_uid: str):
        """Serve the refresh case VirusTotal API endpoint."""
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

    @app.get("/api/reviews")
    def api_reviews(limit: int = 50):
        """Serve the reviews API endpoint."""
        conn = connect(db_path)
        try:
            return list_review_queue(conn, limit)
        finally:
            conn.close()

    @app.post("/api/reviews/{detection_id}")
    def api_submit_review(detection_id: int, payload: AnalystReviewRequest):
        """Serve the submit review API endpoint."""
        action = payload.action.strip().lower()
        if action not in {"confirm", "log_only", "human_review", "investigate", "escalate"}:
            raise HTTPException(status_code=400, detail="Unsupported review action")
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
        """Serve the events API endpoint."""
        conn = connect(db_path)
        try:
            return latest_app_events(conn, limit)
        finally:
            conn.close()

    @app.post("/api/reset-logs")
    def api_reset_logs(payload: ResetLogsRequest):
        """Serve the reset logs API endpoint."""
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
        """Serve the AI status API endpoint."""
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

    return app

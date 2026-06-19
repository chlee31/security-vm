from pathlib import Path
import ipaddress

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
import requests
from pydantic import BaseModel

from app.allowlist import add_allowlist_entry, deactivate_allowlist_entry, list_allowlist_entries
from app.config import load_config
from app.database import (
    connect,
    init_db,
    insert_app_event,
    detection_type_detail,
    detection_time_window,
    enrichment_status,
    latest_alerts,
    latest_app_events,
    latest_decision_evidence,
    latest_ollama_reports,
    list_review_queue,
    submit_analyst_review,
)
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


def create_app(config_path):
    config = load_config(config_path)
    db_path = config.get("database", {}).get("path", "security_vm.db")
    init_db(db_path).close()
    app = FastAPI(title="Security VM Dashboard")
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/")
    def index():
        return FileResponse(STATIC_DIR / "index.html")

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
    def api_detection_detail(detection_type: str, limit: int = 50):
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
    def api_decision_evidence(limit: int = 25, detection_type: str = None):
        conn = connect(db_path)
        try:
            return latest_decision_evidence(conn, limit, detection_type)
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
            by_type = conn.execute(
                "SELECT detection_type, COUNT(*) AS count FROM detections GROUP BY detection_type ORDER BY count DESC"
            ).fetchall()
            return {
                "total_alerts": total_alerts,
                "total_detections": total_detections,
                "detections_by_type": [dict(row) for row in by_type],
                "mode": config.get("system", {}).get("mode"),
            }
        finally:
            conn.close()

    return app

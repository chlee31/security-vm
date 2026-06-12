from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
import requests

from app.config import load_config
from app.database import connect, init_db, insert_app_event, latest_alerts, latest_app_events, latest_ollama_reports
from app.ollama_client import check_ollama


STATIC_DIR = Path(__file__).resolve().parents[1] / "static"


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

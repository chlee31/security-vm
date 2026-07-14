from datetime import datetime, timedelta, timezone
from pathlib import Path
import hashlib
import json

from app.database import insert_incident_evidence, zeek_context_for_detection


def parse_time(value):
    if not value:
        return datetime.now(timezone.utc)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def safe_dir_name(value):
    return "".join(char if char.isalnum() or char in "-_" else "_" for char in str(value))


def write_json(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(payload, indent=2, sort_keys=True)
    path.write_text(text, encoding="utf-8")
    return {
        "path": str(path),
        "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "size_bytes": len(text.encode("utf-8")),
    }


def create_incident_evidence(conn, config, detection_id, seconds_before=None, seconds_after=None, ip_filter_enabled=True):
    incident_config = config.get("incident_evidence", {})
    if not incident_config.get("enabled", True):
        raise ValueError("Incident evidence is disabled in config")
    max_window = int(incident_config.get("maximum_window_seconds", 600))
    seconds_before = int(seconds_before if seconds_before is not None else incident_config.get("seconds_before", 120))
    seconds_after = int(seconds_after if seconds_after is not None else incident_config.get("seconds_after", 120))
    seconds_before = max(1, min(seconds_before, max_window))
    seconds_after = max(1, min(seconds_after, max_window))

    detection = conn.execute("SELECT * FROM detections WHERE id = ?", (detection_id,)).fetchone()
    if not detection:
        raise ValueError(f"Detection {detection_id} not found")
    detection = dict(detection)
    anchor = parse_time(detection.get("first_seen") or detection.get("last_seen"))
    window_start = anchor - timedelta(seconds=seconds_before)
    window_end = anchor + timedelta(seconds=seconds_after)

    root = Path(incident_config.get("root_directory", "/var/lib/security-vm/incidents"))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    directory = root / f"detection_{int(detection_id):06d}_{safe_dir_name(stamp)}"
    zeek_dir = directory / "zeek"
    suricata_dir = directory / "suricata"

    related_alert = None
    if detection.get("first_alert_id"):
        row = conn.execute("SELECT * FROM alerts WHERE id = ?", (detection["first_alert_id"],)).fetchone()
        related_alert = dict(row) if row else None

    zeek_context = zeek_context_for_detection(
        conn,
        detection_id,
        seconds=max(seconds_before, seconds_after),
        limit=500,
    )
    if not ip_filter_enabled:
        zeek_context["ip_filter_note"] = "Current implementation stores IP-filtered context; broad window export is intentionally disabled."

    files = {}
    files["detection"] = write_json(directory / "detection.json", detection)
    if related_alert:
        files["primary_alert"] = write_json(suricata_dir / "primary_alert.json", related_alert)
    files["zeek_events"] = write_json(zeek_dir / "events.json", zeek_context)

    manifest = {
        "detection_id": detection_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "window_start": window_start.isoformat(),
        "window_end": window_end.isoformat(),
        "seconds_before": seconds_before,
        "seconds_after": seconds_after,
        "ip_filter_enabled": bool(ip_filter_enabled),
        "files": files,
        "status": "ready" if zeek_context.get("items") else "partial",
        "notes": [
            "Raw PCAP bytes are not sent to AI by default.",
            "Zeek evidence is filtered by detection time window and endpoint IPs.",
        ],
    }
    files["manifest"] = write_json(directory / "manifest.json", manifest)

    evidence = {
        "detection_id": detection_id,
        "alert_id": detection.get("first_alert_id"),
        "incident_directory": str(directory),
        "incident_start_time": window_start.isoformat(),
        "incident_end_time": window_end.isoformat(),
        "window_start": window_start.isoformat(),
        "window_end": window_end.isoformat(),
        "zeek_logs_path": files["zeek_events"]["path"],
        "evidence_manifest_path": files["manifest"]["path"],
        "status": manifest["status"],
        "error_message": "" if zeek_context.get("items") else "No related Zeek rows found in the evidence window.",
    }
    insert_incident_evidence(conn, evidence)
    row = conn.execute("SELECT * FROM incident_evidence ORDER BY id DESC LIMIT 1").fetchone()
    return dict(row) if row else evidence

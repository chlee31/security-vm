import sqlite3
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path


SCHEMA_PATH = Path(__file__).resolve().parents[1] / "sql" / "schema.sql"


def connect(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path):
    conn = connect(db_path)
    schema = SCHEMA_PATH.read_text(encoding="utf-8")
    conn.executescript(schema)
    ensure_migrations(conn)
    conn.commit()
    return conn


def ensure_migrations(conn):
    columns = {
        row["name"]
        for row in conn.execute("PRAGMA table_info(allowlist)").fetchall()
    }
    if "name" not in columns:
        conn.execute("ALTER TABLE allowlist ADD COLUMN name TEXT")


def insert_alert(conn, alert):
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO alerts (
          suricata_event_id, timestamp, src_ip, dest_ip, src_port, dest_port,
          protocol, signature, category, severity, priority, flow_id, pcap_point, raw_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            alert.get("suricata_event_id"),
            alert.get("timestamp"),
            alert.get("src_ip"),
            alert.get("dest_ip"),
            alert.get("src_port"),
            alert.get("dest_port"),
            alert.get("protocol"),
            alert.get("signature"),
            alert.get("category"),
            alert.get("severity"),
            alert.get("priority"),
            alert.get("flow_id"),
            alert.get("pcap_point"),
            alert.get("raw_json"),
        ),
    )
    conn.commit()
    return cur.lastrowid


def insert_detection(conn, detection):
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO detections (
          first_alert_id, first_seen, last_seen, src_ip, dest_ip, detection_type,
          alert_count, unique_dest_ports, unique_dest_hosts, time_window_seconds,
          mitre_id, mitre_name, python_initial_score, status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            detection.get("first_alert_id"),
            detection.get("first_seen"),
            detection.get("last_seen"),
            detection.get("src_ip"),
            detection.get("dest_ip"),
            detection.get("detection_type"),
            detection.get("alert_count"),
            detection.get("unique_dest_ports"),
            detection.get("unique_dest_hosts"),
            detection.get("time_window_seconds"),
            detection.get("mitre_id"),
            detection.get("mitre_name"),
            detection.get("python_initial_score"),
            detection.get("status"),
        ),
    )
    conn.commit()
    return cur.lastrowid


def insert_ollama_report(conn, detection_id, report):
    conn.execute(
        """
        INSERT INTO ollama_reports (
          detection_id, classification, confidence, risk_adjustment,
          reason, recommended_action, raw_response
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            detection_id,
            report.get("classification"),
            report.get("confidence"),
            report.get("risk_adjustment", 0),
            report.get("reason"),
            report.get("recommended_action"),
            report.get("raw_response"),
        ),
    )
    conn.commit()


def insert_response(conn, response):
    conn.execute(
        """
        INSERT INTO responses (
          detection_id, final_score, final_classification, final_action,
          target_ip, response_method, response_status, response_time_ms
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            response.get("detection_id"),
            response.get("final_score"),
            response.get("final_classification"),
            response.get("final_action"),
            response.get("target_ip"),
            response.get("response_method"),
            response.get("response_status"),
            response.get("response_time_ms"),
        ),
    )
    conn.commit()


def upsert_pending_review(conn, response, review_days=3):
    if response.get("final_action") != "human_review":
        return

    now = datetime.now(timezone.utc)
    due_at = now + timedelta(days=review_days)
    conn.execute(
        """
        INSERT OR IGNORE INTO analyst_reviews (
          detection_id, original_score, original_classification, original_action, due_at
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            response.get("detection_id"),
            response.get("final_score"),
            response.get("final_classification"),
            response.get("final_action"),
            due_at.isoformat(),
        ),
    )
    conn.commit()


def insert_app_event(conn, level, component, message, details=None):
    conn.execute(
        """
        INSERT INTO app_events (level, component, message, details)
        VALUES (?, ?, ?, ?)
        """,
        (
            level,
            component,
            message,
            json.dumps(details, sort_keys=True) if isinstance(details, (dict, list)) else details,
        ),
    )
    conn.commit()


def latest_alerts(conn, limit=50):
    rows = conn.execute(
        "SELECT * FROM alerts ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [dict(row) for row in rows]


def latest_ollama_reports(conn, limit=50):
    rows = conn.execute(
        """
        SELECT
          ollama_reports.id,
          ollama_reports.detection_id,
          ollama_reports.classification,
          ollama_reports.confidence,
          ollama_reports.risk_adjustment,
          ollama_reports.reason,
          ollama_reports.recommended_action,
          ollama_reports.created_at,
          detections.detection_type,
          detections.python_initial_score,
          alerts.timestamp,
          alerts.src_ip,
          alerts.dest_ip,
          alerts.signature
        FROM ollama_reports
        LEFT JOIN detections ON detections.id = ollama_reports.detection_id
        LEFT JOIN alerts ON alerts.id = detections.first_alert_id
        ORDER BY ollama_reports.id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [dict(row) for row in rows]


def latest_app_events(conn, limit=100):
    rows = conn.execute(
        """
        SELECT id, level, component, message, details, created_at
        FROM app_events
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [dict(row) for row in rows]


def expire_stale_reviews(conn):
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """
        UPDATE analyst_reviews
        SET review_status = 'expired'
        WHERE review_status = 'pending'
          AND due_at <= ?
        """,
        (now,),
    )
    conn.commit()


def seed_pending_reviews_from_responses(conn):
    conn.execute(
        """
        INSERT OR IGNORE INTO analyst_reviews (
          detection_id,
          original_score,
          original_classification,
          original_action,
          due_at,
          created_at
        )
        SELECT
          responses.detection_id,
          responses.final_score,
          responses.final_classification,
          responses.final_action,
          datetime(responses.created_at, '+3 days'),
          responses.created_at
        FROM responses
        WHERE responses.final_action = 'human_review'
          AND responses.detection_id IS NOT NULL
        """
    )
    conn.commit()


def list_review_queue(conn, limit=50):
    seed_pending_reviews_from_responses(conn)
    expire_stale_reviews(conn)
    rows = conn.execute(
        """
        SELECT
          analyst_reviews.id,
          analyst_reviews.detection_id,
          analyst_reviews.original_score,
          analyst_reviews.original_classification,
          analyst_reviews.original_action,
          analyst_reviews.review_status,
          analyst_reviews.analyst_name,
          analyst_reviews.analyst_score,
          analyst_reviews.analyst_classification,
          analyst_reviews.analyst_action,
          analyst_reviews.analyst_notes,
          analyst_reviews.due_at,
          analyst_reviews.reviewed_at,
          analyst_reviews.created_at,
          detections.detection_type,
          detections.src_ip,
          detections.dest_ip,
          alerts.signature,
          alerts.timestamp,
          ollama_reports.classification AS ollama_classification,
          ollama_reports.confidence AS ollama_confidence,
          ollama_reports.reason AS ollama_reason
        FROM analyst_reviews
        LEFT JOIN detections ON detections.id = analyst_reviews.detection_id
        LEFT JOIN alerts ON alerts.id = detections.first_alert_id
        LEFT JOIN ollama_reports ON ollama_reports.detection_id = detections.id
        WHERE analyst_reviews.review_status IN ('pending', 'expired')
        ORDER BY
          CASE analyst_reviews.review_status WHEN 'pending' THEN 0 ELSE 1 END,
          analyst_reviews.due_at ASC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [dict(row) for row in rows]


def submit_analyst_review(conn, detection_id, action, analyst_name, notes="", score=None, classification=None):
    now = datetime.now(timezone.utc).isoformat()
    existing = conn.execute(
        "SELECT id, original_score, original_classification, original_action FROM analyst_reviews WHERE detection_id = ?",
        (detection_id,),
    ).fetchone()
    if not existing:
        return False

    if action == "confirm":
        review_status = "confirmed"
        analyst_score = existing["original_score"]
        analyst_classification = existing["original_classification"]
        analyst_action = existing["original_action"]
    else:
        review_status = "overridden"
        analyst_score = score
        analyst_classification = classification
        analyst_action = action

    conn.execute(
        """
        UPDATE analyst_reviews
        SET review_status = ?,
            analyst_name = ?,
            analyst_score = ?,
            analyst_classification = ?,
            analyst_action = ?,
            analyst_notes = ?,
            reviewed_at = ?
        WHERE detection_id = ?
        """,
        (
            review_status,
            analyst_name,
            analyst_score,
            analyst_classification,
            analyst_action,
            notes,
            now,
            detection_id,
        ),
    )
    conn.commit()
    return True


def detections_without_ollama_reports(conn, limit=50):
    rows = conn.execute(
        """
        SELECT
          alerts.id AS alert_id,
          alerts.suricata_event_id,
          alerts.timestamp,
          alerts.src_ip,
          alerts.dest_ip,
          alerts.src_port,
          alerts.dest_port,
          alerts.protocol,
          alerts.signature,
          alerts.category,
          alerts.severity,
          alerts.priority,
          alerts.flow_id,
          alerts.pcap_point,
          alerts.raw_json,
          detections.id AS detection_id,
          detections.first_alert_id,
          detections.first_seen,
          detections.last_seen,
          detections.detection_type,
          detections.alert_count,
          detections.unique_dest_ports,
          detections.unique_dest_hosts,
          detections.time_window_seconds,
          detections.mitre_id,
          detections.mitre_name,
          detections.python_initial_score,
          detections.status
        FROM detections
        JOIN alerts ON alerts.id = detections.first_alert_id
        LEFT JOIN ollama_reports ON ollama_reports.detection_id = detections.id
        WHERE ollama_reports.id IS NULL
        ORDER BY detections.id ASC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [dict(row) for row in rows]

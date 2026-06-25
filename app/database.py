import sqlite3
import json
import ipaddress
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
    allowlist_columns = {
        row["name"]
        for row in conn.execute("PRAGMA table_info(allowlist)").fetchall()
    }
    if "name" not in allowlist_columns:
        conn.execute("ALTER TABLE allowlist ADD COLUMN name TEXT")

    alert_columns = {
        row["name"]
        for row in conn.execute("PRAGMA table_info(alerts)").fetchall()
    }
    if "direction" not in alert_columns:
        conn.execute("ALTER TABLE alerts ADD COLUMN direction TEXT")
    if "capture_iface" not in alert_columns:
        conn.execute("ALTER TABLE alerts ADD COLUMN capture_iface TEXT")


def insert_alert(conn, alert):
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO alerts (
          suricata_event_id, timestamp, src_ip, dest_ip, src_port, dest_port,
          protocol, signature, category, severity, priority, flow_id, pcap_point,
          direction, capture_iface, raw_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            alert.get("direction"),
            alert.get("capture_iface"),
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
    def sqlite_value(value):
        if isinstance(value, (dict, list)):
            return json.dumps(value, sort_keys=True)
        return value

    def sqlite_int(value, default=0):
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

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
            sqlite_value(report.get("classification")),
            sqlite_value(report.get("confidence")),
            sqlite_int(report.get("risk_adjustment", 0)),
            sqlite_value(report.get("reason")),
            sqlite_value(report.get("recommended_action")),
            sqlite_value(report.get("raw_response")),
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


def ip_enrichment_profile(ip_address):
    if not ip_address:
        return {
            "ip_address": "",
            "scope": "unknown",
            "location": "Unknown",
            "source": "none",
            "status": "missing_ip",
        }

    try:
        parsed = ipaddress.ip_address(ip_address)
    except ValueError:
        return {
            "ip_address": ip_address,
            "scope": "invalid",
            "location": "Invalid IP",
            "source": "local-ip-classification",
            "status": "invalid_ip",
        }

    if parsed.is_private:
        scope = "private"
        location = "Internal/private network"
    elif parsed.is_loopback:
        scope = "loopback"
        location = "Local host"
    elif parsed.is_multicast:
        scope = "multicast"
        location = "Multicast"
    elif parsed.is_reserved:
        scope = "reserved"
        location = "Reserved address space"
    else:
        scope = "public"
        location = "Public IP - geo lookup not configured"

    return {
        "ip_address": ip_address,
        "scope": scope,
        "location": location,
        "source": "local-ip-classification",
        "status": "classified",
    }


def detection_type_detail(conn, detection_type, limit=50):
    summary = conn.execute(
        """
        SELECT
          COUNT(*) AS total,
          MIN(first_seen) AS first_seen,
          MAX(last_seen) AS last_seen,
          AVG(python_initial_score) AS avg_score,
          MAX(python_initial_score) AS max_score
        FROM detections
        WHERE detection_type = ?
        """,
        (detection_type,),
    ).fetchone()

    timeline = conn.execute(
        """
        SELECT substr(COALESCE(first_seen, created_at), 1, 13) AS bucket, COUNT(*) AS count
        FROM detections
        WHERE detection_type = ?
        GROUP BY bucket
        ORDER BY bucket ASC
        """,
        (detection_type,),
    ).fetchall()

    ip_rows = conn.execute(
        """
        SELECT ip_address, SUM(count) AS count
        FROM (
          SELECT src_ip AS ip_address, COUNT(*) AS count
          FROM detections
          WHERE detection_type = ? AND src_ip IS NOT NULL
          GROUP BY src_ip
          UNION ALL
          SELECT dest_ip AS ip_address, COUNT(*) AS count
          FROM detections
          WHERE detection_type = ? AND dest_ip IS NOT NULL
          GROUP BY dest_ip
        )
        GROUP BY ip_address
        ORDER BY count DESC
        LIMIT ?
        """,
        (detection_type, detection_type, limit),
    ).fetchall()

    recent = conn.execute(
        """
        SELECT
          detections.id AS detection_id,
          detections.first_seen,
          detections.src_ip,
          detections.dest_ip,
          detections.python_initial_score,
          detections.mitre_id,
          detections.mitre_name,
          alerts.signature,
          alerts.category,
          ollama_reports.classification AS ollama_classification,
          ollama_reports.confidence AS ollama_confidence
        FROM detections
        LEFT JOIN alerts ON alerts.id = detections.first_alert_id
        LEFT JOIN ollama_reports ON ollama_reports.detection_id = detections.id
        WHERE detections.detection_type = ?
        ORDER BY detections.id DESC
        LIMIT ?
        """,
        (detection_type, limit),
    ).fetchall()

    return {
        "detection_type": detection_type,
        "summary": dict(summary) if summary else {},
        "timeline": [dict(row) for row in timeline],
        "ips": [
            {
                **dict(row),
                **ip_enrichment_profile(row["ip_address"]),
            }
            for row in ip_rows
        ],
        "recent": [dict(row) for row in recent],
    }


def detection_time_window(conn, detection_type=None):
    if detection_type:
        row = conn.execute(
            """
            SELECT MIN(first_seen) AS start_time, MAX(last_seen) AS end_time
            FROM detections
            WHERE detection_type = ?
            """,
            (detection_type,),
        ).fetchone()
    else:
        row = conn.execute(
            """
            SELECT MIN(first_seen) AS start_time, MAX(last_seen) AS end_time
            FROM detections
            """
        ).fetchone()
    return dict(row) if row else {"start_time": None, "end_time": None}


def latest_decision_evidence(conn, limit=25, detection_type=None):
    params = []
    filter_sql = ""
    if detection_type:
        filter_sql = "WHERE detections.detection_type = ?"
        params.append(detection_type)
    params.append(limit)

    rows = conn.execute(
        f"""
        SELECT
          responses.id AS response_id,
          responses.detection_id,
          responses.final_score,
          responses.final_classification,
          responses.final_action,
          responses.target_ip,
          responses.response_status,
          responses.created_at AS response_created_at,
          detections.detection_type,
          detections.alert_count,
          detections.unique_dest_ports,
          detections.unique_dest_hosts,
          detections.time_window_seconds,
          detections.mitre_id,
          detections.mitre_name,
          detections.python_initial_score,
          alerts.timestamp,
          alerts.src_ip,
          alerts.dest_ip,
          alerts.src_port,
          alerts.dest_port,
          alerts.protocol,
          alerts.signature,
          alerts.category,
          alerts.priority,
          ollama_reports.classification AS ollama_classification,
          ollama_reports.confidence AS ollama_confidence,
          ollama_reports.risk_adjustment AS ollama_risk_adjustment,
          ollama_reports.reason AS ollama_reason,
          ollama_reports.recommended_action AS ollama_recommended_action,
          analyst_reviews.review_status,
          analyst_reviews.analyst_name,
          analyst_reviews.analyst_score,
          analyst_reviews.analyst_action
        FROM responses
        LEFT JOIN detections ON detections.id = responses.detection_id
        LEFT JOIN alerts ON alerts.id = detections.first_alert_id
        LEFT JOIN ollama_reports ON ollama_reports.detection_id = detections.id
        LEFT JOIN analyst_reviews ON analyst_reviews.detection_id = detections.id
        {filter_sql}
        ORDER BY responses.id DESC
        LIMIT ?
        """,
        params,
    ).fetchall()
    return [dict(row) for row in rows]


def enrichment_status(conn, config, limit=50):
    threat_intel = config.get("threat_intel", {})
    recent_lookups = conn.execute(
        """
        SELECT indicator, indicator_type, source, reputation, malicious_count,
               suspicious_count, lookup_time, cached
        FROM threat_intel_lookups
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    lookup_count = conn.execute("SELECT COUNT(*) AS count FROM threat_intel_lookups").fetchone()["count"]

    ip_rows = conn.execute(
        """
        SELECT ip_address, SUM(count) AS count
        FROM (
          SELECT src_ip AS ip_address, COUNT(*) AS count FROM alerts WHERE src_ip IS NOT NULL GROUP BY src_ip
          UNION ALL
          SELECT dest_ip AS ip_address, COUNT(*) AS count FROM alerts WHERE dest_ip IS NOT NULL GROUP BY dest_ip
        )
        GROUP BY ip_address
        ORDER BY count DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()

    return {
        "sources": [
            {
                "name": "local-ip-classification",
                "enabled": True,
                "status": "active",
                "notes": "Classifies private, loopback, multicast, reserved, and public IPs without external API calls.",
            },
            {
                "name": "virustotal",
                "enabled": bool(threat_intel.get("virustotal_enabled", False)),
                "status": "configured" if threat_intel.get("virustotal_enabled", False) else "disabled",
                "notes": "External reputation lookups are disabled by default to avoid API quota use.",
            },
            {
                "name": "otx",
                "enabled": bool(threat_intel.get("otx_enabled", False)),
                "status": "configured" if threat_intel.get("otx_enabled", False) else "disabled",
                "notes": "AlienVault OTX lookups are disabled by default.",
            },
        ],
        "lookup_count": lookup_count,
        "recent_lookups": [dict(row) for row in recent_lookups],
        "top_ips": [
            {
                **dict(row),
                **ip_enrichment_profile(row["ip_address"]),
            }
            for row in ip_rows
        ],
    }


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


def network_direction_summary(conn):
    rows = conn.execute(
        """
        SELECT
          COALESCE(direction, 'unknown') AS direction,
          COUNT(*) AS count
        FROM alerts
        GROUP BY COALESCE(direction, 'unknown')
        ORDER BY count DESC
        """
    ).fetchall()
    return [dict(row) for row in rows]

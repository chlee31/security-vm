import sqlite3
import json
import ipaddress
import uuid
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

    asset_columns = {
        row["name"]
        for row in conn.execute("PRAGMA table_info(assets)").fetchall()
    }
    if asset_columns:
        if "network_interface" not in asset_columns:
            conn.execute("ALTER TABLE assets ADD COLUMN network_interface TEXT DEFAULT 'ens37'")
        if "status" not in asset_columns:
            conn.execute("ALTER TABLE assets ADD COLUMN status TEXT DEFAULT 'active'")
        if "updated_at" not in asset_columns:
            conn.execute("ALTER TABLE assets ADD COLUMN updated_at TEXT")

    ensure_ai_report_columns(conn, "ai_reports")
    migrate_legacy_ai_reports(conn)

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS ai_profiles (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          uid TEXT NOT NULL UNIQUE,
          name TEXT NOT NULL,
          provider TEXT NOT NULL,
          host TEXT NOT NULL,
          model TEXT NOT NULL,
          timeout_seconds INTEGER DEFAULT 90,
          status TEXT DEFAULT 'active',
          notes TEXT,
          created_at TEXT DEFAULT CURRENT_TIMESTAMP,
          updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
          last_selected_at TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS firewall_blocks (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          detection_id INTEGER,
          ip_address TEXT NOT NULL,
          direction TEXT,
          reason TEXT,
          firewall_rule TEXT,
          timeout_seconds INTEGER,
          status TEXT DEFAULT 'active',
          response_status TEXT,
          response_time_ms INTEGER,
          created_at TEXT DEFAULT CURRENT_TIMESTAMP,
          expires_at TEXT,
          released_at TEXT,
          released_by TEXT,
          release_reason TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS notification_events (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          detection_id INTEGER,
          response_id INTEGER,
          channel TEXT NOT NULL,
          recipient TEXT,
          subject TEXT,
          status TEXT NOT NULL,
          error TEXT,
          cooldown_key TEXT,
          created_at TEXT DEFAULT CURRENT_TIMESTAMP,
          sent_at TEXT
        )
        """
    )


def table_exists(conn, table_name):
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table_name,),
    ).fetchone()
    return row is not None


def ensure_ai_report_columns(conn, table_name):
    if not table_exists(conn, table_name):
        return
    report_columns = {row["name"] for row in conn.execute(f"PRAGMA table_info({table_name})").fetchall()}
    report_migrations = {
        "ai_profile_uid": f"ALTER TABLE {table_name} ADD COLUMN ai_profile_uid TEXT",
        "model_provider": f"ALTER TABLE {table_name} ADD COLUMN model_provider TEXT",
        "model_name": f"ALTER TABLE {table_name} ADD COLUMN model_name TEXT",
        "model_identity": f"ALTER TABLE {table_name} ADD COLUMN model_identity TEXT",
        "model_endpoint": f"ALTER TABLE {table_name} ADD COLUMN model_endpoint TEXT",
        "model_run_id": f"ALTER TABLE {table_name} ADD COLUMN model_run_id TEXT",
        "prompt_version": f"ALTER TABLE {table_name} ADD COLUMN prompt_version TEXT",
        "elapsed_ms": f"ALTER TABLE {table_name} ADD COLUMN elapsed_ms INTEGER",
    }
    for column, statement in report_migrations.items():
        if column not in report_columns:
            conn.execute(statement)


def migrate_legacy_ai_reports(conn):
    legacy_table = "olla" + "ma_reports"
    if not table_exists(conn, legacy_table):
        return
    ensure_ai_report_columns(conn, legacy_table)
    conn.execute(
        f"""
        INSERT OR IGNORE INTO ai_reports (
          id, detection_id, ai_profile_uid, model_provider, model_name,
          model_identity, model_endpoint, model_run_id, prompt_version,
          classification, confidence, risk_adjustment, reason,
          recommended_action, raw_response, elapsed_ms, created_at
        )
        SELECT
          id, detection_id, ai_profile_uid, model_provider, model_name,
          model_identity, model_endpoint, model_run_id, prompt_version,
          classification, confidence, risk_adjustment, reason,
          recommended_action, raw_response, elapsed_ms, created_at
        FROM {legacy_table}
        """
    )


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def normalize_ip(ip_address):
    return str(ipaddress.ip_address(str(ip_address).strip()))


def default_asset_types(config):
    scores = config.get("assets", {}).get("default_scores", {})
    labels = {
        "laptop": "Laptop",
        "desktop": "Desktop",
        "server": "Server",
        "firewall_router": "Firewall / Router",
        "security_appliance": "Security Appliance",
        "printer": "Printer",
        "camera_iot": "Camera / IoT",
        "unknown": "Unknown / Unclassified",
        "other": "Other",
    }
    return [
        {"value": key, "label": labels.get(key, key.replace("_", " ").title()), "default_score": int(value)}
        for key, value in scores.items()
    ]


def default_asset_score(config, device_type):
    scores = config.get("assets", {}).get("default_scores", {})
    return int(scores.get(device_type, scores.get("unknown", 6)))


def new_ai_profile_uid():
    return f"ai-{uuid.uuid4().hex[:12]}"


def list_ai_profiles(conn, limit=100):
    rows = conn.execute(
        """
        SELECT id, uid, name, provider, host, model, timeout_seconds, status,
               notes, created_at, updated_at, last_selected_at
        FROM ai_profiles
        ORDER BY
          CASE status WHEN 'active' THEN 0 ELSE 1 END,
          COALESCE(last_selected_at, updated_at, created_at) DESC,
          id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [dict(row) for row in rows]


def get_ai_profile(conn, uid):
    row = conn.execute(
        """
        SELECT id, uid, name, provider, host, model, timeout_seconds, status,
               notes, created_at, updated_at, last_selected_at
        FROM ai_profiles
        WHERE uid = ?
        """,
        (uid,),
    ).fetchone()
    return dict(row) if row else None


def create_ai_profile(conn, profile):
    uid = profile.get("uid") or new_ai_profile_uid()
    conn.execute(
        """
        INSERT INTO ai_profiles (
          uid, name, provider, host, model, timeout_seconds, status, notes,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            uid,
            profile["name"],
            profile["provider"],
            profile["host"],
            profile["model"],
            int(profile.get("timeout_seconds") or 90),
            profile.get("status", "active"),
            profile.get("notes", ""),
            utc_now(),
        ),
    )
    conn.commit()
    return uid


def update_ai_profile(conn, uid, profile):
    cur = conn.execute(
        """
        UPDATE ai_profiles
        SET name = ?, provider = ?, host = ?, model = ?, timeout_seconds = ?,
            status = ?, notes = ?, updated_at = ?
        WHERE uid = ?
        """,
        (
            profile["name"],
            profile["provider"],
            profile["host"],
            profile["model"],
            int(profile.get("timeout_seconds") or 90),
            profile.get("status", "active"),
            profile.get("notes", ""),
            utc_now(),
            uid,
        ),
    )
    conn.commit()
    return cur.rowcount > 0


def mark_ai_profile_selected(conn, uid):
    cur = conn.execute(
        """
        UPDATE ai_profiles
        SET last_selected_at = ?, updated_at = ?
        WHERE uid = ? AND status = 'active'
        """,
        (utc_now(), utc_now(), uid),
    )
    conn.commit()
    return cur.rowcount > 0


def ensure_ai_profile_from_config(conn, config):
    ai_model = config.setdefault("ai_model", {})
    active_uid = ai_model.get("active_profile_uid")
    if active_uid and get_ai_profile(conn, active_uid):
        return active_uid

    host = (ai_model.get("host") or "").rstrip("/")
    model = ai_model.get("model") or "llama3.1:8b"
    provider = ai_model.get("provider") or "ollama"
    timeout_seconds = int(ai_model.get("timeout_seconds") or 90)
    existing = conn.execute(
        """
        SELECT uid
        FROM ai_profiles
        WHERE host = ? AND model = ? AND provider = ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (host, model, provider),
    ).fetchone()
    if existing:
        uid = existing["uid"]
    else:
        uid = create_ai_profile(
            conn,
            {
                "name": f"{provider}:{model}",
                "provider": provider,
                "host": host,
                "model": model,
                "timeout_seconds": timeout_seconds,
                "status": "active",
                "notes": "Created from current config.yaml AI settings.",
            },
        )
    mark_ai_profile_selected(conn, uid)
    ai_model["active_profile_uid"] = uid
    return uid


def list_assets(conn, limit=100):
    rows = conn.execute(
        """
        SELECT id, ip_address, name, device_type, network_interface, asset_score,
               function, notes, status, created_at, updated_at
        FROM assets
        WHERE status = 'active'
        ORDER BY updated_at DESC, id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [dict(row) for row in rows]


def list_all_assets(conn, limit=500):
    rows = conn.execute(
        """
        SELECT id, ip_address, name, device_type, network_interface, asset_score,
               function, notes, status, created_at, updated_at
        FROM assets
        ORDER BY status ASC, updated_at DESC, id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [dict(row) for row in rows]


def lookup_asset(conn, ip_address):
    if not ip_address:
        return None
    row = conn.execute(
        """
        SELECT id, ip_address, name, device_type, network_interface, asset_score,
               function, notes, status, created_at, updated_at
        FROM assets
        WHERE ip_address = ? AND status = 'active'
        """,
        (ip_address,),
    ).fetchone()
    return dict(row) if row else None


def asset_context_for_alert(conn, alert):
    src_asset = lookup_asset(conn, alert.get("src_ip"))
    dest_asset = lookup_asset(conn, alert.get("dest_ip"))
    matched_asset = src_asset or dest_asset
    return {
        "src_asset": src_asset,
        "dest_asset": dest_asset,
        "matched_asset": matched_asset,
        "asset_score": int(matched_asset["asset_score"]) if matched_asset else 0,
        "asset_match": "src_ip" if src_asset else "dest_ip" if dest_asset else "none",
    }


def upsert_asset(conn, asset):
    now = utc_now()
    ip_address = normalize_ip(asset.get("ip_address"))
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO assets (
          ip_address, name, device_type, network_interface, asset_score,
          function, notes, status, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)
        ON CONFLICT(ip_address) DO UPDATE SET
          name = excluded.name,
          device_type = excluded.device_type,
          network_interface = excluded.network_interface,
          asset_score = excluded.asset_score,
          function = excluded.function,
          notes = excluded.notes,
          status = 'active',
          updated_at = excluded.updated_at
        """,
        (
            ip_address,
            asset.get("name"),
            asset.get("device_type"),
            asset.get("network_interface") or "ens37",
            int(asset.get("asset_score")),
            asset.get("function"),
            asset.get("notes"),
            now,
            now,
        ),
    )
    conn.commit()
    row = conn.execute("SELECT id FROM assets WHERE ip_address = ?", (ip_address,)).fetchone()
    return row["id"] if row else cur.lastrowid


def deactivate_asset(conn, asset_id):
    cur = conn.execute(
        "UPDATE assets SET status = 'inactive', updated_at = ? WHERE id = ?",
        (utc_now(), asset_id),
    )
    conn.commit()
    return cur.rowcount > 0


def delete_asset(conn, asset_id):
    cur = conn.execute("DELETE FROM assets WHERE id = ?", (asset_id,))
    conn.commit()
    return cur.rowcount > 0


def update_asset(conn, asset_id, asset):
    now = utc_now()
    ip_address = normalize_ip(asset.get("ip_address"))
    cur = conn.execute(
        """
        UPDATE assets
        SET ip_address = ?,
            name = ?,
            device_type = ?,
            network_interface = ?,
            asset_score = ?,
            function = ?,
            notes = ?,
            status = ?,
            updated_at = ?
        WHERE id = ?
        """,
        (
            ip_address,
            asset.get("name"),
            asset.get("device_type"),
            asset.get("network_interface") or "ens37",
            int(asset.get("asset_score")),
            asset.get("function"),
            asset.get("notes"),
            asset.get("status") or "active",
            now,
            asset_id,
        ),
    )
    conn.commit()
    return cur.rowcount > 0


def asset_summary(conn):
    rows = conn.execute(
        """
        SELECT device_type, COUNT(*) AS count, AVG(asset_score) AS avg_score
        FROM assets
        WHERE status = 'active'
        GROUP BY device_type
        ORDER BY count DESC
        """
    ).fetchall()
    total = conn.execute("SELECT COUNT(*) AS count FROM assets WHERE status = 'active'").fetchone()["count"]
    return {"total": total, "by_type": [dict(row) for row in rows]}


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


def insert_ai_report(conn, detection_id, report):
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
        INSERT INTO ai_reports (
          detection_id, ai_profile_uid, model_provider, model_name, model_identity,
          model_endpoint, model_run_id, prompt_version, classification, confidence,
          risk_adjustment, reason, recommended_action, raw_response, elapsed_ms
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            detection_id,
            sqlite_value(report.get("ai_profile_uid")),
            sqlite_value(report.get("model_provider")),
            sqlite_value(report.get("model_name")),
            sqlite_value(report.get("model_identity")),
            sqlite_value(report.get("model_endpoint")),
            sqlite_value(report.get("model_run_id")),
            sqlite_value(report.get("prompt_version")),
            sqlite_value(report.get("classification")),
            sqlite_value(report.get("confidence")),
            sqlite_int(report.get("risk_adjustment", 0)),
            sqlite_value(report.get("reason")),
            sqlite_value(report.get("recommended_action")),
            sqlite_value(report.get("raw_response")),
            sqlite_int(report.get("elapsed_ms", 0)),
        ),
    )
    conn.commit()


def insert_response(conn, response):
    cur = conn.execute(
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
    return cur.lastrowid


def insert_notification_event(conn, event):
    now = utc_now()
    cur = conn.execute(
        """
        INSERT INTO notification_events (
          detection_id, response_id, channel, recipient, subject, status,
          error, cooldown_key, created_at, sent_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event.get("detection_id"),
            event.get("response_id"),
            event.get("channel", "email"),
            event.get("recipient"),
            event.get("subject"),
            event.get("status"),
            event.get("error"),
            event.get("cooldown_key"),
            now,
            now if event.get("status") == "sent" else None,
        ),
    )
    conn.commit()
    return cur.lastrowid


def list_notification_events(conn, limit=50):
    rows = conn.execute(
        """
        SELECT notification_events.*, detections.src_ip, detections.dest_ip,
               detections.detection_type, responses.final_score,
               responses.final_classification
        FROM notification_events
        LEFT JOIN detections ON detections.id = notification_events.detection_id
        LEFT JOIN responses ON responses.id = notification_events.response_id
        ORDER BY notification_events.id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [dict(row) for row in rows]


def latest_sent_notification(conn, cooldown_key):
    row = conn.execute(
        """
        SELECT *
        FROM notification_events
        WHERE cooldown_key = ?
          AND status = 'sent'
        ORDER BY id DESC
        LIMIT 1
        """,
        (cooldown_key,),
    ).fetchone()
    return dict(row) if row else None


def insert_firewall_block(conn, block):
    now = datetime.now(timezone.utc)
    timeout_seconds = int(block.get("timeout_seconds") or 0)
    expires_at = now + timedelta(seconds=timeout_seconds) if timeout_seconds else None
    cur = conn.execute(
        """
        INSERT INTO firewall_blocks (
          detection_id, ip_address, direction, reason, firewall_rule, timeout_seconds,
          status, response_status, response_time_ms, created_at, expires_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            block.get("detection_id"),
            normalize_ip(block.get("ip_address")),
            block.get("direction"),
            block.get("reason"),
            block.get("firewall_rule"),
            timeout_seconds,
            block.get("status") or "active",
            block.get("response_status"),
            block.get("response_time_ms"),
            now.isoformat(),
            expires_at.isoformat() if expires_at else None,
        ),
    )
    conn.commit()
    return cur.lastrowid


def list_firewall_blocks(conn, limit=100, status="active"):
    if status == "all":
        rows = conn.execute(
            """
            SELECT firewall_blocks.*, detections.src_ip, detections.dest_ip, detections.detection_type,
                   alerts.signature
            FROM firewall_blocks
            LEFT JOIN detections ON detections.id = firewall_blocks.detection_id
            LEFT JOIN alerts ON alerts.id = detections.first_alert_id
            ORDER BY firewall_blocks.id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT firewall_blocks.*, detections.src_ip, detections.dest_ip, detections.detection_type,
                   alerts.signature
            FROM firewall_blocks
            LEFT JOIN detections ON detections.id = firewall_blocks.detection_id
            LEFT JOIN alerts ON alerts.id = detections.first_alert_id
            WHERE firewall_blocks.status = ?
            ORDER BY firewall_blocks.id DESC
            LIMIT ?
            """,
            (status, limit),
        ).fetchall()
    return [dict(row) for row in rows]


def firewall_candidate_target(row):
    item = dict(row)
    src_ip = item.get("src_ip")
    dest_ip = item.get("dest_ip")
    target_ip = item.get("target_ip")
    direction = "source"
    try:
        src = ipaddress.ip_address(src_ip) if src_ip else None
        dest = ipaddress.ip_address(dest_ip) if dest_ip else None
        if src and dest and src.is_private and not dest.is_private:
            target_ip = dest_ip
            direction = "outbound_destination"
    except ValueError:
        pass
    item["target_ip"] = target_ip
    item["target_direction"] = direction
    return item


def list_firewall_candidates(conn, limit=50):
    rows = conn.execute(
        """
        SELECT
          responses.id AS response_id,
          responses.detection_id,
          responses.final_score,
          responses.final_classification,
          responses.final_action,
          responses.target_ip,
          responses.response_status,
          responses.created_at AS response_created_at,
          detections.src_ip,
          detections.dest_ip,
          detections.detection_type,
          alerts.signature
        FROM responses
        LEFT JOIN detections ON detections.id = responses.detection_id
        LEFT JOIN alerts ON alerts.id = detections.first_alert_id
        WHERE responses.final_action = 'would_block'
          AND responses.target_ip IS NOT NULL
          AND NOT EXISTS (
            SELECT 1
            FROM firewall_blocks
            WHERE firewall_blocks.detection_id = responses.detection_id
              AND firewall_blocks.ip_address = responses.target_ip
              AND firewall_blocks.status = 'active'
          )
        ORDER BY responses.id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [firewall_candidate_target(row) for row in rows]


def list_firewall_history(conn, limit=100):
    block_rows = conn.execute(
        """
        SELECT
          'block' AS history_type,
          firewall_blocks.id AS item_id,
          firewall_blocks.detection_id,
          firewall_blocks.ip_address,
          firewall_blocks.direction,
          firewall_blocks.reason,
          firewall_blocks.status,
          firewall_blocks.response_status,
          firewall_blocks.created_at,
          firewall_blocks.released_at,
          firewall_blocks.released_by,
          firewall_blocks.release_reason,
          detections.src_ip,
          detections.dest_ip,
          detections.detection_type,
          alerts.signature
        FROM firewall_blocks
        LEFT JOIN detections ON detections.id = firewall_blocks.detection_id
        LEFT JOIN alerts ON alerts.id = detections.first_alert_id
        ORDER BY firewall_blocks.id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    safe_rows = conn.execute(
        """
        SELECT
          'marked_safe' AS history_type,
          responses.id AS item_id,
          responses.detection_id,
          responses.target_ip AS ip_address,
          NULL AS direction,
          responses.final_classification AS reason,
          responses.final_action AS status,
          responses.response_status,
          responses.created_at,
          NULL AS released_at,
          NULL AS released_by,
          NULL AS release_reason,
          detections.src_ip,
          detections.dest_ip,
          detections.detection_type,
          alerts.signature
        FROM responses
        LEFT JOIN detections ON detections.id = responses.detection_id
        LEFT JOIN alerts ON alerts.id = detections.first_alert_id
        WHERE responses.response_status = 'marked_safe'
           OR responses.final_action = 'authorized_activity'
        ORDER BY responses.id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    rows = [dict(row) for row in block_rows] + [dict(row) for row in safe_rows]
    rows.sort(key=lambda item: item.get("released_at") or item.get("created_at") or "", reverse=True)
    return rows[:limit]


def get_firewall_candidate(conn, response_id):
    row = conn.execute(
        """
        SELECT
          responses.id AS response_id,
          responses.detection_id,
          responses.final_score,
          responses.final_classification,
          responses.final_action,
          responses.target_ip,
          responses.response_status,
          responses.created_at AS response_created_at,
          detections.src_ip,
          detections.dest_ip,
          detections.detection_type,
          alerts.signature
        FROM responses
        LEFT JOIN detections ON detections.id = responses.detection_id
        LEFT JOIN alerts ON alerts.id = detections.first_alert_id
        WHERE responses.id = ?
          AND responses.final_action = 'would_block'
          AND responses.target_ip IS NOT NULL
        LIMIT 1
        """,
        (response_id,),
    ).fetchone()
    return firewall_candidate_target(row) if row else None


def update_response_manual_action(conn, response_id, final_classification, final_action, response_method, response_status, response_time_ms=0):
    cur = conn.execute(
        """
        UPDATE responses
        SET final_classification = ?,
            final_action = ?,
            response_method = ?,
            response_status = ?,
            response_time_ms = ?
        WHERE id = ?
        """,
        (
            final_classification,
            final_action,
            response_method,
            response_status,
            response_time_ms,
            response_id,
        ),
    )
    conn.commit()
    return cur.rowcount > 0


def get_firewall_block(conn, block_id):
    row = conn.execute(
        """
        SELECT *
        FROM firewall_blocks
        WHERE id = ?
        """,
        (block_id,),
    ).fetchone()
    return dict(row) if row else None


def release_firewall_block(conn, block_id, released_by="admin", reason="manual unblock"):
    cur = conn.execute(
        """
        UPDATE firewall_blocks
        SET status = 'released',
            released_at = ?,
            released_by = ?,
            release_reason = ?
        WHERE id = ?
        """,
        (datetime.now(timezone.utc).isoformat(), released_by, reason, block_id),
    )
    conn.commit()
    return cur.rowcount > 0


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


def reset_dashboard_logs(conn):
    tables = [
        "alerts",
        "detections",
        "ai_reports",
        "responses",
        "incident_evidence",
        "analyst_reviews",
        "tuning_labels",
        "app_events",
        "threat_intel_lookups",
        "notification_events",
    ]
    counts = {}
    for table in tables:
        counts[table] = conn.execute(f"SELECT COUNT(*) AS count FROM {table}").fetchone()["count"]
        conn.execute(f"DELETE FROM {table}")
    conn.commit()
    return counts


def latest_alerts(conn, limit=50):
    rows = conn.execute(
        """
        SELECT
          alerts.*,
          detections.id AS detection_id,
          detections.detection_type,
          responses.final_score,
          responses.final_classification
        FROM alerts
        LEFT JOIN detections ON detections.first_alert_id = alerts.id
        LEFT JOIN responses ON responses.detection_id = detections.id
        ORDER BY alerts.id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [dict(row) for row in rows]


def latest_ai_opinions(conn, limit=50):
    rows = conn.execute(
        """
        SELECT
          ai_reports.id,
          ai_reports.detection_id,
          ai_reports.ai_profile_uid,
          ai_reports.model_provider,
          ai_reports.model_name,
          ai_reports.model_identity,
          ai_reports.model_endpoint,
          ai_reports.model_run_id,
          ai_reports.prompt_version,
          ai_reports.classification,
          ai_reports.confidence,
          ai_reports.risk_adjustment,
          ai_reports.reason,
          ai_reports.recommended_action,
          ai_reports.elapsed_ms,
          ai_reports.created_at,
          detections.detection_type,
          detections.python_initial_score,
          alerts.timestamp,
          alerts.src_ip,
          alerts.dest_ip,
          alerts.signature
        FROM ai_reports
        LEFT JOIN detections ON detections.id = ai_reports.detection_id
        LEFT JOIN alerts ON alerts.id = detections.first_alert_id
        ORDER BY ai_reports.id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [dict(row) for row in rows]


def ai_model_comparison(conn):
    rows = conn.execute(
        """
        SELECT
          COALESCE(model_identity, 'unknown model') AS model_identity,
          COALESCE(ai_profile_uid, 'legacy-profile') AS ai_profile_uid,
          COALESCE(model_provider, 'unknown') AS model_provider,
          COALESCE(model_name, 'unknown') AS model_name,
          COALESCE(classification, 'No opinion') AS classification,
          COUNT(*) AS count,
          AVG(COALESCE(risk_adjustment, 0)) AS avg_risk_adjustment,
          AVG(COALESCE(elapsed_ms, 0)) AS avg_elapsed_ms
        FROM ai_reports
        GROUP BY ai_profile_uid, model_identity, classification
        ORDER BY ai_profile_uid ASC, count DESC
        """
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


def latest_threat_intel_for_ip(conn, ip_address, source=None):
    if not ip_address:
        return None
    params = [ip_address]
    source_filter = ""
    if source:
        source_filter = "AND lower(source) = ?"
        params.append(source.lower())
    row = conn.execute(
        f"""
        SELECT indicator, indicator_type, source, reputation, malicious_count,
               suspicious_count, lookup_time, cached, lookup_result
        FROM threat_intel_lookups
        WHERE indicator = ?
          {source_filter}
        ORDER BY lookup_time DESC, id DESC
        LIMIT 1
        """,
        params,
    ).fetchone()
    return dict(row) if row else None


def upsert_threat_intel_lookup(
    conn,
    indicator,
    source,
    reputation,
    malicious_count=0,
    suspicious_count=0,
    lookup_result="",
    raw_response="",
    indicator_type="ip",
    cached=0,
):
    conn.execute(
        """
        INSERT INTO threat_intel_lookups (
          indicator, indicator_type, source, lookup_result, malicious_count,
          suspicious_count, reputation, lookup_time, cached, raw_response
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            indicator,
            indicator_type,
            source,
            lookup_result,
            int(malicious_count or 0),
            int(suspicious_count or 0),
            reputation,
            utc_now(),
            int(cached or 0),
            raw_response,
        ),
    )
    conn.commit()


def public_ips_for_enrichment(conn, limit=10, detection_type=None):
    if detection_type:
        rows = conn.execute(
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
            (detection_type, detection_type, limit * 4),
        ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT ip_address, SUM(count) AS count
            FROM (
              SELECT src_ip AS ip_address, COUNT(*) AS count FROM alerts WHERE src_ip IS NOT NULL GROUP BY src_ip
              UNION ALL
              SELECT dest_ip AS ip_address, COUNT(*) AS count FROM alerts WHERE dest_ip IS NOT NULL GROUP BY dest_ip
              UNION ALL
              SELECT src_ip AS ip_address, COUNT(*) AS count FROM detections WHERE src_ip IS NOT NULL GROUP BY src_ip
              UNION ALL
              SELECT dest_ip AS ip_address, COUNT(*) AS count FROM detections WHERE dest_ip IS NOT NULL GROUP BY dest_ip
            )
            GROUP BY ip_address
            ORDER BY count DESC
            LIMIT ?
            """,
            (limit * 4,),
        ).fetchall()

    candidates = []
    for row in rows:
        ip_address = row["ip_address"]
        try:
            parsed = ipaddress.ip_address(ip_address)
        except ValueError:
            continue
        if parsed.is_private or parsed.is_loopback or parsed.is_multicast or parsed.is_reserved:
            continue
        candidates.append({"ip_address": ip_address, "count": row["count"]})
        if len(candidates) >= limit:
            break
    return candidates


def detection_type_detail(conn, detection_type=None, limit=50):
    filter_sql = "WHERE detection_type = ?" if detection_type else ""
    params = [detection_type] if detection_type else []

    summary = conn.execute(
        f"""
        SELECT
          COUNT(*) AS total,
          MIN(first_seen) AS first_seen,
          MAX(last_seen) AS last_seen,
          AVG(python_initial_score) AS avg_score,
          MAX(python_initial_score) AS max_score
        FROM detections
        {filter_sql}
        """,
        params,
    ).fetchone()

    timeline = conn.execute(
        f"""
        SELECT substr(COALESCE(first_seen, created_at), 1, 13) AS bucket, COUNT(*) AS count
        FROM detections
        {filter_sql}
        GROUP BY bucket
        ORDER BY bucket ASC
        """,
        params,
    ).fetchall()

    src_filter = "WHERE detection_type = ? AND src_ip IS NOT NULL" if detection_type else "WHERE src_ip IS NOT NULL"
    dest_filter = "WHERE detection_type = ? AND dest_ip IS NOT NULL" if detection_type else "WHERE dest_ip IS NOT NULL"
    ip_params = [detection_type, detection_type, limit] if detection_type else [limit]
    ip_rows = conn.execute(
        f"""
        SELECT ip_address, SUM(count) AS count
        FROM (
          SELECT src_ip AS ip_address, COUNT(*) AS count
          FROM detections
          {src_filter}
          GROUP BY src_ip
          UNION ALL
          SELECT dest_ip AS ip_address, COUNT(*) AS count
          FROM detections
          {dest_filter}
          GROUP BY dest_ip
        )
        GROUP BY ip_address
        ORDER BY count DESC
        LIMIT ?
        """,
        ip_params,
    ).fetchall()

    recent_filter = "WHERE detections.detection_type = ?" if detection_type else ""
    recent_params = [detection_type, limit] if detection_type else [limit]
    recent = conn.execute(
        f"""
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
          ai_reports.classification AS ai_classification,
          ai_reports.confidence AS ai_confidence,
          ai_reports.ai_profile_uid AS ai_profile_uid,
          ai_reports.model_identity AS ai_model_identity
        FROM detections
        LEFT JOIN alerts ON alerts.id = detections.first_alert_id
        LEFT JOIN ai_reports ON ai_reports.detection_id = detections.id
        {recent_filter}
        ORDER BY detections.id DESC
        LIMIT ?
        """,
        recent_params,
    ).fetchall()

    enriched_ips = []
    for row in ip_rows:
        item = {
            **dict(row),
            **ip_enrichment_profile(row["ip_address"]),
        }
        item["asset"] = lookup_asset(conn, row["ip_address"])
        item["otx"] = latest_threat_intel_for_ip(conn, row["ip_address"], "otx")
        enriched_ips.append(item)

    recent_rows = []
    for row in recent:
        item = dict(row)
        item["src_asset"] = lookup_asset(conn, item.get("src_ip"))
        item["dest_asset"] = lookup_asset(conn, item.get("dest_ip"))
        recent_rows.append(item)

    return {
        "detection_type": detection_type or "all_traffic",
        "summary": dict(summary) if summary else {},
        "timeline": [dict(row) for row in timeline],
        "ips": enriched_ips,
        "recent": recent_rows,
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


def latest_decision_evidence(conn, limit=25, detection_type=None, outcome=None):
    params = []
    filters = []
    if detection_type:
        filters.append("detections.detection_type = ?")
        params.append(detection_type)
    if outcome == "dangerous":
        filters.append(
            """
            (
              lower(COALESCE(responses.final_classification, '')) LIKE '%dangerous%'
              OR responses.final_action IN ('would_block', 'temporary_block')
            )
            """
        )
    elif outcome == "human_review":
        filters.append(
            """
            (
              lower(COALESCE(responses.final_classification, '')) LIKE '%human%'
              OR responses.final_action = 'human_review'
            )
            """
        )
    elif outcome == "safe":
        filters.append(
            """
            NOT (
              lower(COALESCE(responses.final_classification, '')) LIKE '%dangerous%'
              OR responses.final_action IN ('would_block', 'temporary_block')
              OR lower(COALESCE(responses.final_classification, '')) LIKE '%human%'
              OR responses.final_action = 'human_review'
            )
            """
        )
    filter_sql = f"WHERE {' AND '.join(filters)}" if filters else ""
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
          ai_reports.classification AS ai_classification,
          ai_reports.confidence AS ai_confidence,
          ai_reports.risk_adjustment AS ai_risk_adjustment,
          ai_reports.reason AS ai_reason,
          ai_reports.recommended_action AS ai_recommended_action,
          ai_reports.ai_profile_uid AS ai_profile_uid,
          ai_reports.model_provider AS ai_model_provider,
          ai_reports.model_name AS ai_model_name,
          ai_reports.model_identity AS ai_model_identity,
          ai_reports.model_run_id AS ai_model_run_id,
          ai_reports.prompt_version AS ai_prompt_version,
          ai_reports.elapsed_ms AS ai_elapsed_ms,
          analyst_reviews.review_status,
          analyst_reviews.analyst_name,
          analyst_reviews.analyst_score,
          analyst_reviews.analyst_action
        FROM responses
        LEFT JOIN detections ON detections.id = responses.detection_id
        LEFT JOIN alerts ON alerts.id = detections.first_alert_id
        LEFT JOIN ai_reports ON ai_reports.detection_id = detections.id
        LEFT JOIN analyst_reviews ON analyst_reviews.detection_id = detections.id
        {filter_sql}
        ORDER BY responses.id DESC
        LIMIT ?
        """,
        params,
    ).fetchall()
    evidence = []
    for row in rows:
        item = dict(row)
        item["src_asset"] = lookup_asset(conn, item.get("src_ip"))
        item["dest_asset"] = lookup_asset(conn, item.get("dest_ip"))
        evidence.append(item)
    return evidence


def investigation_detail(conn, detection_id):
    row = conn.execute(
        """
        SELECT
          detections.id AS detection_id,
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
          detections.status AS detection_status,
          alerts.id AS alert_id,
          alerts.timestamp,
          alerts.src_ip,
          alerts.dest_ip,
          alerts.src_port,
          alerts.dest_port,
          alerts.protocol,
          alerts.signature,
          alerts.category,
          alerts.priority,
          alerts.raw_json,
          ai_reports.classification AS ai_classification,
          ai_reports.confidence AS ai_confidence,
          ai_reports.risk_adjustment AS ai_risk_adjustment,
          ai_reports.reason AS ai_reason,
          ai_reports.recommended_action AS ai_recommended_action,
          ai_reports.raw_response AS ai_raw_response,
          ai_reports.ai_profile_uid AS ai_profile_uid,
          ai_reports.model_provider AS ai_model_provider,
          ai_reports.model_name AS ai_model_name,
          ai_reports.model_identity AS ai_model_identity,
          ai_reports.model_endpoint AS ai_model_endpoint,
          ai_reports.model_run_id AS ai_model_run_id,
          ai_reports.prompt_version AS ai_prompt_version,
          ai_reports.elapsed_ms AS ai_elapsed_ms,
          ai_reports.created_at AS ai_created_at,
          responses.final_score,
          responses.final_classification,
          responses.final_action,
          responses.target_ip,
          responses.response_status,
          responses.response_time_ms,
          responses.created_at AS response_created_at,
          analyst_reviews.review_status,
          analyst_reviews.analyst_name,
          analyst_reviews.analyst_score,
          analyst_reviews.analyst_classification,
          analyst_reviews.analyst_action,
          analyst_reviews.analyst_notes,
          analyst_reviews.due_at,
          analyst_reviews.reviewed_at
        FROM detections
        LEFT JOIN alerts ON alerts.id = detections.first_alert_id
        LEFT JOIN ai_reports ON ai_reports.detection_id = detections.id
        LEFT JOIN responses ON responses.detection_id = detections.id
        LEFT JOIN analyst_reviews ON analyst_reviews.detection_id = detections.id
        WHERE detections.id = ?
        ORDER BY responses.id DESC, ai_reports.id DESC
        LIMIT 1
        """,
        (detection_id,),
    ).fetchone()
    if not row:
        return None

    item = dict(row)
    item["src_asset"] = lookup_asset(conn, item.get("src_ip"))
    item["dest_asset"] = lookup_asset(conn, item.get("dest_ip"))
    item["src_ip_profile"] = ip_enrichment_profile(item.get("src_ip"))
    item["dest_ip_profile"] = ip_enrichment_profile(item.get("dest_ip"))
    item["src_otx"] = latest_threat_intel_for_ip(conn, item.get("src_ip"), "otx")
    item["dest_otx"] = latest_threat_intel_for_ip(conn, item.get("dest_ip"), "otx")
    return item


def enrichment_status(conn, config, limit=50):
    threat_intel = config.get("threat_intel", {})
    cache_ttl_hours = int(threat_intel.get("cache_ttl_hours", 24))
    otx_enabled = bool(threat_intel.get("otx_enabled", False))
    otx_key_configured = bool(threat_intel.get("otx_api_key"))
    if otx_enabled and otx_key_configured:
        otx_status = "ready"
        otx_notes = "AlienVault OTX manual lookups are enabled. Use Run OTX Lookups to cache reputation results."
    elif otx_enabled:
        otx_status = "missing_key"
        otx_notes = "OTX is enabled but no API key is configured."
    else:
        otx_status = "disabled"
        otx_notes = "AlienVault OTX lookups are disabled."
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
                "status": "configured" if threat_intel.get("virustotal_enabled", False) else "planned_disabled",
                "notes": "Optional external reputation source. Python will call the API only when enabled and cache results before the AI model sees them.",
                "cache_ttl_hours": cache_ttl_hours,
                "api_key_configured": bool(threat_intel.get("virustotal_api_key")),
            },
            {
                "name": "otx",
                "enabled": otx_enabled,
                "status": otx_status,
                "notes": otx_notes,
                "cache_ttl_hours": cache_ttl_hours,
                "api_key_configured": otx_key_configured,
            },
        ],
        "cache_policy": {
            "enabled": True,
            "ttl_hours": cache_ttl_hours,
            "notes": "Reuse recent SQLite threat_intel_lookups rows to avoid burning API quota.",
        },
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
          ai_reports.classification AS ai_classification,
          ai_reports.confidence AS ai_confidence,
          ai_reports.reason AS ai_reason,
          ai_reports.ai_profile_uid AS ai_profile_uid,
          ai_reports.model_identity AS ai_model_identity
        FROM analyst_reviews
        LEFT JOIN detections ON detections.id = analyst_reviews.detection_id
        LEFT JOIN alerts ON alerts.id = detections.first_alert_id
        LEFT JOIN ai_reports ON ai_reports.detection_id = detections.id
        WHERE analyst_reviews.review_status IN ('pending', 'expired')
        ORDER BY
          CASE analyst_reviews.review_status WHEN 'pending' THEN 0 ELSE 1 END,
          analyst_reviews.due_at ASC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [dict(row) for row in rows]


def submit_analyst_review(
    conn,
    detection_id,
    action,
    analyst_name,
    notes="",
    score=None,
    classification=None,
    tuning_label=None,
):
    now = datetime.now(timezone.utc).isoformat()
    existing = conn.execute(
        "SELECT id, original_score, original_classification, original_action FROM analyst_reviews WHERE detection_id = ?",
        (detection_id,),
    ).fetchone()
    if not existing:
        source = conn.execute(
            """
            SELECT
              responses.final_score,
              responses.final_classification,
              responses.final_action,
              detections.python_initial_score
            FROM detections
            LEFT JOIN responses ON responses.detection_id = detections.id
            WHERE detections.id = ?
            ORDER BY responses.id DESC
            LIMIT 1
            """,
            (detection_id,),
        ).fetchone()
        if not source:
            return False
        original_score = source["final_score"]
        if original_score is None:
            original_score = source["python_initial_score"] or 0
        original_classification = source["final_classification"] or "Human Review Required"
        original_action = source["final_action"] or "human_review"
        conn.execute(
            """
            INSERT INTO analyst_reviews (
              detection_id, original_score, original_classification, original_action, due_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                detection_id,
                original_score,
                original_classification,
                original_action,
                (datetime.now(timezone.utc) + timedelta(days=3)).isoformat(),
            ),
        )
        existing = {
            "original_score": original_score,
            "original_classification": original_classification,
            "original_action": original_action,
        }

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
    if tuning_label:
        conn.execute(
            """
            INSERT INTO tuning_labels (
              detection_id, label, false_positive_reason, analyst_notes
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                detection_id,
                tuning_label,
                notes if tuning_label in {"false_positive", "authorized_test"} else None,
                notes,
            ),
        )
    conn.commit()
    return True


def detections_without_ai_reports(conn, limit=50, model_identity=None, ai_profile_uid=None):
    join_filters = []
    params = []
    if ai_profile_uid:
        join_filters.append("AND ai_reports.ai_profile_uid = ?")
        params.append(ai_profile_uid)
    elif model_identity:
        join_filters.append("AND ai_reports.model_identity = ?")
        params.append(model_identity)
    join_filter = " ".join(join_filters)
    params.append(limit)
    rows = conn.execute(
        f"""
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
        LEFT JOIN ai_reports
          ON ai_reports.detection_id = detections.id
          {join_filter}
        WHERE ai_reports.id IS NULL
        ORDER BY detections.id ASC
        LIMIT ?
        """,
        params,
    ).fetchall()
    return [dict(row) for row in rows]

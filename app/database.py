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

    report_columns = {
        row["name"]
        for row in conn.execute("PRAGMA table_info(ollama_reports)").fetchall()
    }
    if report_columns:
        report_migrations = {
            "ai_profile_uid": "ALTER TABLE ollama_reports ADD COLUMN ai_profile_uid TEXT",
            "model_provider": "ALTER TABLE ollama_reports ADD COLUMN model_provider TEXT",
            "model_name": "ALTER TABLE ollama_reports ADD COLUMN model_name TEXT",
            "model_identity": "ALTER TABLE ollama_reports ADD COLUMN model_identity TEXT",
            "model_endpoint": "ALTER TABLE ollama_reports ADD COLUMN model_endpoint TEXT",
            "model_run_id": "ALTER TABLE ollama_reports ADD COLUMN model_run_id TEXT",
            "prompt_version": "ALTER TABLE ollama_reports ADD COLUMN prompt_version TEXT",
            "elapsed_ms": "ALTER TABLE ollama_reports ADD COLUMN elapsed_ms INTEGER",
            "prompt_sha256": "ALTER TABLE ollama_reports ADD COLUMN prompt_sha256 TEXT",
            "prompt_chars": "ALTER TABLE ollama_reports ADD COLUMN prompt_chars INTEGER",
            "pcap_summary_sha256": "ALTER TABLE ollama_reports ADD COLUMN pcap_summary_sha256 TEXT",
            "pcap_summary_chars": "ALTER TABLE ollama_reports ADD COLUMN pcap_summary_chars INTEGER",
            "pcap_summary_included": "ALTER TABLE ollama_reports ADD COLUMN pcap_summary_included INTEGER DEFAULT 0",
        }
        for column, statement in report_migrations.items():
            if column not in report_columns:
                conn.execute(statement)

    evidence_columns = {
        row["name"]
        for row in conn.execute("PRAGMA table_info(incident_evidence)").fetchall()
    }
    if evidence_columns:
        evidence_migrations = {
            "capture_label": "ALTER TABLE incident_evidence ADD COLUMN capture_label TEXT",
            "file_size_bytes": "ALTER TABLE incident_evidence ADD COLUMN file_size_bytes INTEGER",
            "pcap_modified_at": "ALTER TABLE incident_evidence ADD COLUMN pcap_modified_at TEXT",
            "summary_status": "ALTER TABLE incident_evidence ADD COLUMN summary_status TEXT",
            "summary_packet_count": "ALTER TABLE incident_evidence ADD COLUMN summary_packet_count INTEGER",
            "summary_error": "ALTER TABLE incident_evidence ADD COLUMN summary_error TEXT",
            "display_filter": "ALTER TABLE incident_evidence ADD COLUMN display_filter TEXT",
            "ai_sent": "ALTER TABLE incident_evidence ADD COLUMN ai_sent INTEGER DEFAULT 0",
            "ai_model_run_id": "ALTER TABLE incident_evidence ADD COLUMN ai_model_run_id TEXT",
        }
        for column, statement in evidence_migrations.items():
            if column not in evidence_columns:
                conn.execute(statement)

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
    ollama = config.setdefault("ollama", {})
    active_uid = ollama.get("active_profile_uid")
    if active_uid and get_ai_profile(conn, active_uid):
        return active_uid

    host = (ollama.get("host") or "").rstrip("/")
    model = ollama.get("model") or "llama3.1:8b"
    provider = ollama.get("provider") or "ollama"
    timeout_seconds = int(ollama.get("timeout_seconds") or 90)
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
    ollama["active_profile_uid"] = uid
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
          detection_id, ai_profile_uid, model_provider, model_name, model_identity,
          model_endpoint, model_run_id, prompt_version, classification, confidence,
          risk_adjustment, reason, recommended_action, raw_response, elapsed_ms,
          prompt_sha256, prompt_chars, pcap_summary_sha256,
          pcap_summary_chars, pcap_summary_included
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            sqlite_value(report.get("prompt_sha256")),
            sqlite_int(report.get("prompt_chars", 0)),
            sqlite_value(report.get("pcap_summary_sha256")),
            sqlite_int(report.get("pcap_summary_chars", 0)),
            sqlite_int(report.get("pcap_summary_included", 0)),
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


def insert_incident_evidence(conn, evidence):
    conn.execute(
        """
        INSERT INTO incident_evidence (
          detection_id, alert_id, incident_start_time, incident_end_time,
          incident_pcap_path, pcap_summary_path, capture_label,
          file_size_bytes, pcap_modified_at, summary_status,
          summary_packet_count, summary_error, display_filter, ai_sent,
          ai_model_run_id
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            evidence.get("detection_id"),
            evidence.get("alert_id"),
            evidence.get("incident_start_time"),
            evidence.get("incident_end_time"),
            evidence.get("incident_pcap_path"),
            evidence.get("pcap_summary_path"),
            evidence.get("capture_label"),
            evidence.get("file_size_bytes"),
            evidence.get("pcap_modified_at"),
            evidence.get("summary_status"),
            evidence.get("summary_packet_count"),
            evidence.get("summary_error"),
            evidence.get("display_filter"),
            1 if evidence.get("ai_sent") else 0,
            evidence.get("ai_model_run_id"),
        ),
    )
    conn.commit()


def list_incident_evidence(conn, detection_id, preview_chars=6000):
    rows = conn.execute(
        """
        SELECT
          id, detection_id, alert_id, incident_start_time, incident_end_time,
          incident_pcap_path, pcap_summary_path, capture_label,
          file_size_bytes, pcap_modified_at, summary_status,
          summary_packet_count, summary_error, display_filter, ai_sent,
          ai_model_run_id, created_at
        FROM incident_evidence
        WHERE detection_id = ?
        ORDER BY id ASC
        """,
        (detection_id,),
    ).fetchall()

    evidence = []
    for row in rows:
        item = dict(row)
        summary_path = item.get("pcap_summary_path")
        if summary_path:
            try:
                text = Path(summary_path).read_text(encoding="utf-8", errors="replace")
                item["pcap_summary_preview"] = text[:preview_chars]
                item["pcap_summary_truncated"] = len(text) > preview_chars
            except OSError as exc:
                item["pcap_summary_preview"] = ""
                item["pcap_summary_error"] = str(exc)
                item["pcap_summary_truncated"] = False
        else:
            item["pcap_summary_preview"] = ""
            item["pcap_summary_truncated"] = False
        evidence.append(item)
    return evidence


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
        "ollama_reports",
        "responses",
        "incident_evidence",
        "analyst_reviews",
        "tuning_labels",
        "app_events",
        "threat_intel_lookups",
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


def latest_ollama_reports(conn, limit=50):
    rows = conn.execute(
        """
        SELECT
          ollama_reports.id,
          ollama_reports.detection_id,
          ollama_reports.ai_profile_uid,
          ollama_reports.model_provider,
          ollama_reports.model_name,
          ollama_reports.model_identity,
          ollama_reports.model_endpoint,
          ollama_reports.model_run_id,
          ollama_reports.prompt_version,
          ollama_reports.classification,
          ollama_reports.confidence,
          ollama_reports.risk_adjustment,
          ollama_reports.reason,
          ollama_reports.recommended_action,
          ollama_reports.elapsed_ms,
          ollama_reports.prompt_sha256,
          ollama_reports.prompt_chars,
          ollama_reports.pcap_summary_sha256,
          ollama_reports.pcap_summary_chars,
          ollama_reports.pcap_summary_included,
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
        FROM ollama_reports
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
          ollama_reports.classification AS ollama_classification,
          ollama_reports.confidence AS ollama_confidence,
          ollama_reports.ai_profile_uid AS ollama_ai_profile_uid,
          ollama_reports.model_identity AS ollama_model_identity
        FROM detections
        LEFT JOIN alerts ON alerts.id = detections.first_alert_id
        LEFT JOIN ollama_reports ON ollama_reports.detection_id = detections.id
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
          ollama_reports.classification AS ollama_classification,
          ollama_reports.confidence AS ollama_confidence,
          ollama_reports.risk_adjustment AS ollama_risk_adjustment,
          ollama_reports.reason AS ollama_reason,
          ollama_reports.recommended_action AS ollama_recommended_action,
          ollama_reports.ai_profile_uid AS ollama_ai_profile_uid,
          ollama_reports.model_provider AS ollama_model_provider,
          ollama_reports.model_name AS ollama_model_name,
          ollama_reports.model_identity AS ollama_model_identity,
          ollama_reports.model_run_id AS ollama_model_run_id,
          ollama_reports.prompt_version AS ollama_prompt_version,
          ollama_reports.elapsed_ms AS ollama_elapsed_ms,
          ollama_reports.prompt_sha256 AS ollama_prompt_sha256,
          ollama_reports.prompt_chars AS ollama_prompt_chars,
          ollama_reports.pcap_summary_sha256 AS ollama_pcap_summary_sha256,
          ollama_reports.pcap_summary_chars AS ollama_pcap_summary_chars,
          ollama_reports.pcap_summary_included AS ollama_pcap_summary_included,
          (
            SELECT COUNT(*)
            FROM incident_evidence
            WHERE incident_evidence.detection_id = detections.id
          ) AS pcap_evidence_count,
          (
            SELECT COUNT(*)
            FROM incident_evidence
            WHERE incident_evidence.detection_id = detections.id
              AND incident_evidence.ai_sent = 1
          ) AS pcap_ai_sent_count,
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
          ollama_reports.classification AS ai_classification,
          ollama_reports.confidence AS ai_confidence,
          ollama_reports.risk_adjustment AS ai_risk_adjustment,
          ollama_reports.reason AS ai_reason,
          ollama_reports.recommended_action AS ai_recommended_action,
          ollama_reports.raw_response AS ai_raw_response,
          ollama_reports.ai_profile_uid AS ai_profile_uid,
          ollama_reports.model_provider AS ai_model_provider,
          ollama_reports.model_name AS ai_model_name,
          ollama_reports.model_identity AS ai_model_identity,
          ollama_reports.model_endpoint AS ai_model_endpoint,
          ollama_reports.model_run_id AS ai_model_run_id,
          ollama_reports.prompt_version AS ai_prompt_version,
          ollama_reports.elapsed_ms AS ai_elapsed_ms,
          ollama_reports.prompt_sha256 AS ai_prompt_sha256,
          ollama_reports.prompt_chars AS ai_prompt_chars,
          ollama_reports.pcap_summary_sha256 AS ai_pcap_summary_sha256,
          ollama_reports.pcap_summary_chars AS ai_pcap_summary_chars,
          ollama_reports.pcap_summary_included AS ai_pcap_summary_included,
          ollama_reports.created_at AS ai_created_at,
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
        LEFT JOIN ollama_reports ON ollama_reports.detection_id = detections.id
        LEFT JOIN responses ON responses.detection_id = detections.id
        LEFT JOIN analyst_reviews ON analyst_reviews.detection_id = detections.id
        WHERE detections.id = ?
        ORDER BY responses.id DESC, ollama_reports.id DESC
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
          ollama_reports.classification AS ollama_classification,
          ollama_reports.confidence AS ollama_confidence,
          ollama_reports.reason AS ollama_reason,
          ollama_reports.ai_profile_uid AS ollama_ai_profile_uid,
          ollama_reports.model_identity AS ollama_model_identity
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


def detections_without_ollama_reports(conn, limit=50, model_identity=None, ai_profile_uid=None):
    join_filters = []
    params = []
    if ai_profile_uid:
        join_filters.append("AND ollama_reports.ai_profile_uid = ?")
        params.append(ai_profile_uid)
    elif model_identity:
        join_filters.append("AND ollama_reports.model_identity = ?")
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
        LEFT JOIN ollama_reports
          ON ollama_reports.detection_id = detections.id
          {join_filter}
        WHERE ollama_reports.id IS NULL
        ORDER BY detections.id ASC
        LIMIT ?
        """,
        params,
    ).fetchall()
    return [dict(row) for row in rows]

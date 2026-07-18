import sqlite3
import json
import ipaddress
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path


SCHEMA_PATH = Path(__file__).resolve().parents[1] / "sql" / "schema.sql"


def connect(db_path):
    conn = sqlite3.connect(db_path, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


def init_db(db_path):
    conn = connect(db_path)
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    ensure_pre_schema_columns(conn)
    schema = SCHEMA_PATH.read_text(encoding="utf-8")
    conn.executescript(schema)
    ensure_migrations(conn)
    conn.commit()
    return conn


def ensure_pre_schema_columns(conn):
    """Add columns required by schema indexes before CREATE IF NOT EXISTS runs."""
    required_columns = {
        "alerts": {"event_uid": "TEXT"},
        "detections": {"case_uid": "TEXT"},
        "zeek_events": {
            "event_uid": "TEXT",
            "source_ip": "TEXT",
            "destination_ip": "TEXT",
        },
    }
    for table_name, requirements in required_columns.items():
        if not table_exists(conn, table_name):
            continue
        columns = {
            row["name"]
            for row in conn.execute(f"PRAGMA table_info({table_name})").fetchall()
        }
        for column, column_type in requirements.items():
            if column not in columns:
                conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {column} {column_type}")


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
    ensure_incident_evidence_columns(conn)
    ensure_zeek_tables(conn)
    ensure_ai_assessments_table(conn)
    ensure_threat_intel_tables(conn)
    ensure_sensor_fusion_tables(conn)
    ensure_case_identity_columns(conn)
    ensure_decision_audit_tables(conn)
    ensure_ai_comparison_tables(conn)
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
          zone TEXT,
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
    firewall_columns = {
        row["name"] for row in conn.execute("PRAGMA table_info(firewall_blocks)").fetchall()
    }
    if "zone" not in firewall_columns:
        conn.execute("ALTER TABLE firewall_blocks ADD COLUMN zone TEXT")
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


def ensure_ai_comparison_tables(conn):
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS ai_comparison_runs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          comparison_uid TEXT NOT NULL UNIQUE,
          case_uid TEXT NOT NULL,
          detection_id INTEGER NOT NULL,
          evidence_sha256 TEXT,
          threat_intel_evidence_json TEXT,
          prompt_version TEXT,
          status TEXT NOT NULL DEFAULT 'pending',
          candidate_count INTEGER NOT NULL DEFAULT 0,
          error_message TEXT,
          created_at TEXT DEFAULT CURRENT_TIMESTAMP,
          completed_at TEXT,
          FOREIGN KEY (detection_id) REFERENCES detections(id)
        );
        CREATE INDEX IF NOT EXISTS idx_ai_comparison_runs_case
          ON ai_comparison_runs(case_uid, id DESC);
        CREATE TABLE IF NOT EXISTS ai_comparison_candidates (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          comparison_run_id INTEGER NOT NULL,
          anonymous_slot TEXT NOT NULL,
          ai_profile_uid TEXT NOT NULL,
          model_provider TEXT,
          model_name TEXT,
          model_identity TEXT,
          model_run_id TEXT,
          prompt_version TEXT,
          prompt_sha256 TEXT,
          classification TEXT,
          confidence TEXT,
          risk_adjustment INTEGER,
          summary TEXT,
          who_summary TEXT,
          what_summary TEXT,
          when_summary TEXT,
          where_summary TEXT,
          why_summary TEXT,
          how_summary TEXT,
          next_steps_json TEXT,
          threat_intel_analysis_json TEXT,
          recommended_action TEXT,
          raw_response TEXT,
          elapsed_ms INTEGER,
          status TEXT NOT NULL DEFAULT 'complete',
          error_message TEXT,
          created_at TEXT DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (comparison_run_id) REFERENCES ai_comparison_runs(id),
          UNIQUE(comparison_run_id, anonymous_slot),
          UNIQUE(comparison_run_id, ai_profile_uid)
        );
        CREATE TABLE IF NOT EXISTS ai_comparison_votes (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          comparison_run_id INTEGER NOT NULL,
          analyst_name TEXT NOT NULL,
          selection TEXT NOT NULL,
          notes TEXT,
          created_at TEXT DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (comparison_run_id) REFERENCES ai_comparison_runs(id)
        );
        CREATE INDEX IF NOT EXISTS idx_ai_comparison_votes_run
          ON ai_comparison_votes(comparison_run_id, id DESC);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_ai_comparison_votes_one_per_run
          ON ai_comparison_votes(comparison_run_id);
        """
    )
    run_columns = {
        row["name"] for row in conn.execute("PRAGMA table_info(ai_comparison_runs)").fetchall()
    }
    if "threat_intel_evidence_json" not in run_columns:
        conn.execute("ALTER TABLE ai_comparison_runs ADD COLUMN threat_intel_evidence_json TEXT")
    candidate_columns = {
        row["name"] for row in conn.execute("PRAGMA table_info(ai_comparison_candidates)").fetchall()
    }
    if "threat_intel_analysis_json" not in candidate_columns:
        conn.execute("ALTER TABLE ai_comparison_candidates ADD COLUMN threat_intel_analysis_json TEXT")


def table_exists(conn, table_name):
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table_name,),
    ).fetchone()
    return row is not None


def _uid_date(value):
    try:
        parsed = datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
    except ValueError:
        parsed = datetime.now(timezone.utc)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).strftime("%Y%m%d")


def stable_record_uid(prefix, record_id, timestamp):
    return f"{prefix}-{_uid_date(timestamp)}-{int(record_id):06d}"


def ensure_case_identity_columns(conn):
    definitions = {
        "alerts": ("event_uid", "SUR", "timestamp"),
        "detections": ("case_uid", "CASE", "first_seen"),
        "zeek_events": ("event_uid", "ZEK", "timestamp"),
    }
    for table_name, (column, prefix, timestamp_column) in definitions.items():
        if not table_exists(conn, table_name):
            continue
        columns = {
            row["name"]
            for row in conn.execute(f"PRAGMA table_info({table_name})").fetchall()
        }
        if column not in columns:
            conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {column} TEXT")
        rows = conn.execute(
            f"SELECT id, {timestamp_column} AS event_time FROM {table_name} "
            f"WHERE {column} IS NULL OR {column} = '' ORDER BY id"
        ).fetchall()
        for row in rows:
            conn.execute(
                f"UPDATE {table_name} SET {column} = ? WHERE id = ?",
                (stable_record_uid(prefix, row["id"], row["event_time"]), row["id"]),
            )
        conn.execute(
            f"CREATE UNIQUE INDEX IF NOT EXISTS idx_{table_name}_{column} "
            f"ON {table_name}({column})"
        )


def ensure_decision_audit_tables(conn):
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS score_breakdowns (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          detection_id INTEGER NOT NULL,
          ai_report_id INTEGER,
          assessment_type TEXT NOT NULL DEFAULT 'initial',
          sensor_severity INTEGER NOT NULL DEFAULT 0,
          behavior_correlation INTEGER NOT NULL DEFAULT 0,
          threat_intelligence INTEGER NOT NULL DEFAULT 0,
          mitre_relevance INTEGER NOT NULL DEFAULT 0,
          asset_direction INTEGER NOT NULL DEFAULT 0,
          sensor_corroboration INTEGER NOT NULL DEFAULT 0,
          python_score INTEGER NOT NULL DEFAULT 0,
          llm_adjustment_raw INTEGER NOT NULL DEFAULT 0,
          llm_adjustment_applied INTEGER NOT NULL DEFAULT 0,
          provisional_score INTEGER NOT NULL DEFAULT 0,
          forced_review INTEGER NOT NULL DEFAULT 0,
          forced_review_reason TEXT,
          details_json TEXT,
          created_at TEXT DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (detection_id) REFERENCES detections(id),
          FOREIGN KEY (ai_report_id) REFERENCES ai_reports(id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS virustotal_verifications (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          detection_id INTEGER NOT NULL,
          ai_report_id INTEGER,
          assessment_stage TEXT NOT NULL DEFAULT 'initial',
          ip_address TEXT,
          request_state TEXT NOT NULL,
          verdict TEXT NOT NULL DEFAULT 'unknown',
          interpretation TEXT NOT NULL DEFAULT 'unavailable',
          malicious_count INTEGER NOT NULL DEFAULT 0,
          suspicious_count INTEGER NOT NULL DEFAULT 0,
          cached INTEGER NOT NULL DEFAULT 0,
          details_json TEXT,
          error TEXT,
          checked_at TEXT DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (detection_id) REFERENCES detections(id),
          FOREIGN KEY (ai_report_id) REFERENCES ai_reports(id)
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_score_breakdowns_detection "
        "ON score_breakdowns(detection_id, assessment_type)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_vt_verifications_detection "
        "ON virustotal_verifications(detection_id, assessment_stage)"
    )


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
        "prompt_sha256": f"ALTER TABLE {table_name} ADD COLUMN prompt_sha256 TEXT",
        "prompt_chars": f"ALTER TABLE {table_name} ADD COLUMN prompt_chars INTEGER",
        # Retained only so pre-scope-change databases can be migrated safely.
        "pcap_summary_sha256": f"ALTER TABLE {table_name} ADD COLUMN pcap_summary_sha256 TEXT",
        "pcap_summary_chars": f"ALTER TABLE {table_name} ADD COLUMN pcap_summary_chars INTEGER",
        "pcap_summary_included": f"ALTER TABLE {table_name} ADD COLUMN pcap_summary_included INTEGER DEFAULT 0",
        "summary": f"ALTER TABLE {table_name} ADD COLUMN summary TEXT",
        "who_summary": f"ALTER TABLE {table_name} ADD COLUMN who_summary TEXT",
        "what_summary": f"ALTER TABLE {table_name} ADD COLUMN what_summary TEXT",
        "when_summary": f"ALTER TABLE {table_name} ADD COLUMN when_summary TEXT",
        "where_summary": f"ALTER TABLE {table_name} ADD COLUMN where_summary TEXT",
        "why_summary": f"ALTER TABLE {table_name} ADD COLUMN why_summary TEXT",
        "how_summary": f"ALTER TABLE {table_name} ADD COLUMN how_summary TEXT",
        "next_steps_json": f"ALTER TABLE {table_name} ADD COLUMN next_steps_json TEXT",
        "threat_intel_analysis_json": f"ALTER TABLE {table_name} ADD COLUMN threat_intel_analysis_json TEXT",
    }
    for column, statement in report_migrations.items():
        if column not in report_columns:
            conn.execute(statement)


def ensure_incident_evidence_columns(conn):
    if not table_exists(conn, "incident_evidence"):
        return
    evidence_columns = {row["name"] for row in conn.execute("PRAGMA table_info(incident_evidence)").fetchall()}
    evidence_migrations = {
        "incident_directory": "ALTER TABLE incident_evidence ADD COLUMN incident_directory TEXT",
        "window_start": "ALTER TABLE incident_evidence ADD COLUMN window_start TEXT",
        "window_end": "ALTER TABLE incident_evidence ADD COLUMN window_end TEXT",
        "pcap_path": "ALTER TABLE incident_evidence ADD COLUMN pcap_path TEXT",
        "zeek_logs_path": "ALTER TABLE incident_evidence ADD COLUMN zeek_logs_path TEXT",
        "pcap_summary": "ALTER TABLE incident_evidence ADD COLUMN pcap_summary TEXT",
        "evidence_manifest_path": "ALTER TABLE incident_evidence ADD COLUMN evidence_manifest_path TEXT",
        "status": "ALTER TABLE incident_evidence ADD COLUMN status TEXT DEFAULT 'pending'",
        "error_message": "ALTER TABLE incident_evidence ADD COLUMN error_message TEXT",
        "capture_label": "ALTER TABLE incident_evidence ADD COLUMN capture_label TEXT",
        "file_size_bytes": "ALTER TABLE incident_evidence ADD COLUMN file_size_bytes INTEGER",
        "pcap_modified_at": "ALTER TABLE incident_evidence ADD COLUMN pcap_modified_at TEXT",
        "summary_status": "ALTER TABLE incident_evidence ADD COLUMN summary_status TEXT",
        "summary_packet_count": "ALTER TABLE incident_evidence ADD COLUMN summary_packet_count INTEGER",
        "summary_error": "ALTER TABLE incident_evidence ADD COLUMN summary_error TEXT",
        "display_filter": "ALTER TABLE incident_evidence ADD COLUMN display_filter TEXT",
        "ai_sent": "ALTER TABLE incident_evidence ADD COLUMN ai_sent INTEGER DEFAULT 0",
        "ai_model_run_id": "ALTER TABLE incident_evidence ADD COLUMN ai_model_run_id TEXT",
        "updated_at": "ALTER TABLE incident_evidence ADD COLUMN updated_at TEXT",
    }
    for column, statement in evidence_migrations.items():
        if column not in evidence_columns:
            conn.execute(statement)


def ensure_zeek_tables(conn):
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS zeek_events (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          zeek_uid TEXT,
          log_type TEXT NOT NULL,
          timestamp TEXT NOT NULL,
          source_ip TEXT,
          source_port INTEGER,
          destination_ip TEXT,
          destination_port INTEGER,
          protocol TEXT,
          community_id TEXT,
          event_name TEXT,
          message TEXT,
          sub_message TEXT,
          actions_json TEXT,
          raw_json TEXT NOT NULL,
          ingested_at TEXT NOT NULL,
          UNIQUE(log_type, timestamp, zeek_uid, event_name, message)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS zeek_ingest_checkpoints (
          log_type TEXT PRIMARY KEY,
          path TEXT,
          inode INTEGER,
          offset INTEGER DEFAULT 0,
          updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_zeek_events_time ON zeek_events(timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_zeek_events_uid ON zeek_events(zeek_uid)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_zeek_events_src_dst ON zeek_events(source_ip, destination_ip)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_incident_evidence_detection ON incident_evidence(detection_id)")

    columns = {row["name"] for row in conn.execute("PRAGMA table_info(zeek_events)").fetchall()}
    migrations = {
        "source_ip": "ALTER TABLE zeek_events ADD COLUMN source_ip TEXT",
        "source_port": "ALTER TABLE zeek_events ADD COLUMN source_port INTEGER",
        "destination_ip": "ALTER TABLE zeek_events ADD COLUMN destination_ip TEXT",
        "destination_port": "ALTER TABLE zeek_events ADD COLUMN destination_port INTEGER",
        "protocol": "ALTER TABLE zeek_events ADD COLUMN protocol TEXT",
        "community_id": "ALTER TABLE zeek_events ADD COLUMN community_id TEXT",
        "event_name": "ALTER TABLE zeek_events ADD COLUMN event_name TEXT",
        "message": "ALTER TABLE zeek_events ADD COLUMN message TEXT",
        "sub_message": "ALTER TABLE zeek_events ADD COLUMN sub_message TEXT",
        "actions_json": "ALTER TABLE zeek_events ADD COLUMN actions_json TEXT",
    }
    for column, statement in migrations.items():
        if column not in columns:
            conn.execute(statement)


def ensure_sensor_fusion_tables(conn):
    alert_columns = {row["name"] for row in conn.execute("PRAGMA table_info(alerts)").fetchall()}
    if "community_id" not in alert_columns:
        conn.execute("ALTER TABLE alerts ADD COLUMN community_id TEXT")

    detection_columns = {row["name"] for row in conn.execute("PRAGMA table_info(detections)").fetchall()}
    migrations = {
        "src_port": "ALTER TABLE detections ADD COLUMN src_port INTEGER",
        "dest_port": "ALTER TABLE detections ADD COLUMN dest_port INTEGER",
        "protocol": "ALTER TABLE detections ADD COLUMN protocol TEXT",
        "community_id": "ALTER TABLE detections ADD COLUMN community_id TEXT",
        "sensor_state": "ALTER TABLE detections ADD COLUMN sensor_state TEXT DEFAULT 'suricata_only'",
        "agreement_state": "ALTER TABLE detections ADD COLUMN agreement_state TEXT DEFAULT 'single_sensor'",
        "correlation_method": "ALTER TABLE detections ADD COLUMN correlation_method TEXT DEFAULT 'single_sensor'",
        "correlation_confidence": "ALTER TABLE detections ADD COLUMN correlation_confidence REAL DEFAULT 0.5",
    }
    for column, statement in migrations.items():
        if column not in detection_columns:
            conn.execute(statement)

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sensor_findings (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          detection_id INTEGER NOT NULL,
          sensor TEXT NOT NULL,
          sensor_event_id INTEGER NOT NULL,
          finding_type TEXT NOT NULL,
          finding_name TEXT NOT NULL,
          severity INTEGER,
          confidence REAL,
          community_id TEXT,
          raw_event TEXT,
          created_at TEXT DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(sensor, sensor_event_id),
          FOREIGN KEY (detection_id) REFERENCES detections(id)
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sensor_findings_detection ON sensor_findings(detection_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sensor_findings_event ON sensor_findings(sensor, sensor_event_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_detections_community ON detections(community_id)")


def ensure_ai_assessments_table(conn):
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS ai_assessments (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          detection_id INTEGER NOT NULL,
          incident_evidence_id INTEGER,
          assessment_type TEXT NOT NULL,
          provider TEXT,
          model_name TEXT NOT NULL,
          classification TEXT NOT NULL,
          confidence REAL,
          risk_adjustment INTEGER,
          reason TEXT,
          recommended_action TEXT,
          evidence_sources_json TEXT,
          response_time_ms INTEGER,
          raw_response TEXT,
          created_at TEXT NOT NULL,
          FOREIGN KEY (detection_id) REFERENCES detections(id),
          FOREIGN KEY (incident_evidence_id) REFERENCES incident_evidence(id)
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ai_assessments_detection ON ai_assessments(detection_id, assessment_type)")


def ensure_threat_intel_tables(conn):
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS threat_intel_indicators (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          indicator TEXT NOT NULL,
          indicator_type TEXT NOT NULL,
          source TEXT NOT NULL,
          category TEXT,
          malware_family TEXT,
          confidence INTEGER,
          first_seen TEXT,
          last_seen TEXT,
          expires_at TEXT,
          source_reference TEXT,
          raw_data TEXT,
          imported_at TEXT NOT NULL,
          UNIQUE(indicator, indicator_type, source)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS threat_intel_sources (
          source TEXT PRIMARY KEY,
          status TEXT NOT NULL DEFAULT 'not_active',
          indicator_count INTEGER DEFAULT 0,
          last_attempt TEXT,
          last_success TEXT,
          last_error TEXT,
          updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS threat_intel_usage (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          detection_id INTEGER,
          alert_id INTEGER,
          indicator TEXT NOT NULL,
          indicator_type TEXT NOT NULL,
          source TEXT NOT NULL,
          stage TEXT NOT NULL,
          matched INTEGER DEFAULT 1,
          details_json TEXT,
          used_at TEXT NOT NULL,
          UNIQUE(detection_id, indicator, indicator_type, source, stage)
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_threat_intel_indicator ON threat_intel_indicators(indicator, indicator_type)"
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_threat_intel_source ON threat_intel_indicators(source)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_threat_intel_usage_source ON threat_intel_usage(source, used_at)")


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
          recommended_action, raw_response, elapsed_ms, prompt_sha256,
          prompt_chars, pcap_summary_sha256, pcap_summary_chars,
          pcap_summary_included, created_at
        )
        SELECT
          id, detection_id, ai_profile_uid, model_provider, model_name,
          model_identity, model_endpoint, model_run_id, prompt_version,
          classification, confidence, risk_adjustment, reason,
          recommended_action, raw_response, elapsed_ms, prompt_sha256,
          prompt_chars, pcap_summary_sha256, pcap_summary_chars,
          pcap_summary_included, created_at
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


def new_ai_comparison_uid():
    return f"cmp-{uuid.uuid4().hex[:16]}"


def create_ai_comparison_run(
    conn,
    case_uid,
    detection_id,
    evidence_sha256,
    prompt_version,
    threat_intel_evidence=None,
):
    comparison_uid = new_ai_comparison_uid()
    cur = conn.execute(
        """
        INSERT INTO ai_comparison_runs (
          comparison_uid, case_uid, detection_id, evidence_sha256, prompt_version,
          threat_intel_evidence_json,
          status, candidate_count
        )
        VALUES (?, ?, ?, ?, ?, ?, 'running', 0)
        """,
        (
            comparison_uid,
            case_uid,
            detection_id,
            evidence_sha256,
            prompt_version,
            json.dumps(threat_intel_evidence or {}, sort_keys=True),
        ),
    )
    conn.commit()
    return cur.lastrowid, comparison_uid


def insert_ai_comparison_candidate(conn, comparison_run_id, slot, profile_uid, report=None, error=None):
    report = report or {}
    status = "failed" if error else "complete"
    cur = conn.execute(
        """
        INSERT INTO ai_comparison_candidates (
          comparison_run_id, anonymous_slot, ai_profile_uid, model_provider,
          model_name, model_identity, model_run_id, prompt_version, prompt_sha256,
          classification, confidence, risk_adjustment, summary, who_summary,
          what_summary, when_summary, where_summary, why_summary, how_summary,
          next_steps_json, threat_intel_analysis_json, recommended_action,
          raw_response, elapsed_ms, status,
          error_message
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            comparison_run_id,
            slot,
            profile_uid,
            report.get("model_provider"),
            report.get("model_name"),
            report.get("model_identity"),
            report.get("model_run_id"),
            report.get("prompt_version"),
            report.get("prompt_sha256"),
            report.get("classification"),
            report.get("confidence"),
            int(report.get("risk_adjustment") or 0),
            report.get("summary"),
            report.get("who"),
            report.get("what"),
            report.get("when"),
            report.get("where"),
            report.get("why"),
            report.get("how"),
            json.dumps(report.get("next_steps") or []),
            json.dumps(report.get("threat_intel_analysis") or {}, sort_keys=True),
            report.get("recommended_action"),
            report.get("raw_response"),
            int(report.get("elapsed_ms") or 0),
            status,
            str(error) if error else None,
        ),
    )
    conn.commit()
    return cur.lastrowid


def finish_ai_comparison_run(conn, comparison_run_id, status, candidate_count, error_message=None):
    conn.execute(
        """
        UPDATE ai_comparison_runs
        SET status = ?, candidate_count = ?, error_message = ?, completed_at = ?
        WHERE id = ?
        """,
        (status, int(candidate_count), error_message, utc_now(), comparison_run_id),
    )
    conn.commit()


def _comparison_votes(conn, comparison_run_id):
    rows = conn.execute(
        """
        SELECT id, analyst_name, selection, notes, created_at
        FROM ai_comparison_votes
        WHERE comparison_run_id = ?
        ORDER BY id DESC
        """,
        (comparison_run_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def ai_comparison_detail(conn, comparison_uid):
    run = conn.execute(
        """
        SELECT id, comparison_uid, case_uid, detection_id, evidence_sha256,
               prompt_version, threat_intel_evidence_json, status,
               candidate_count, error_message,
               created_at, completed_at
        FROM ai_comparison_runs
        WHERE comparison_uid = ?
        """,
        (comparison_uid,),
    ).fetchone()
    if not run:
        return None
    result = dict(run)
    votes = _comparison_votes(conn, result["id"])
    rows = conn.execute(
        """
        SELECT id, anonymous_slot, ai_profile_uid, model_provider, model_name,
               model_identity, model_run_id, prompt_version, prompt_sha256,
               classification, confidence, risk_adjustment, summary,
               who_summary, what_summary, when_summary, where_summary,
               why_summary, how_summary, next_steps_json,
               threat_intel_analysis_json, recommended_action,
               raw_response, elapsed_ms, status, error_message, created_at
        FROM ai_comparison_candidates
        WHERE comparison_run_id = ?
        ORDER BY anonymous_slot
        """,
        (result["id"],),
    ).fetchall()
    candidates = []
    try:
        result["threat_intel_evidence"] = json.loads(
            result.pop("threat_intel_evidence_json") or "{}"
        )
    except (TypeError, ValueError):
        result["threat_intel_evidence"] = {}
    for row in rows:
        item = dict(row)
        try:
            item["next_steps"] = json.loads(item.pop("next_steps_json") or "[]")
        except (TypeError, ValueError):
            item["next_steps"] = []
        try:
            item["threat_intel_analysis"] = json.loads(
                item.pop("threat_intel_analysis_json") or "{}"
            )
        except (TypeError, ValueError):
            item["threat_intel_analysis"] = {}
        if item.get("raw_response") and (
            item.get("summary") in {None, "", "AI model did not provide a reason."}
            or item.get("who_summary") == "Not established from the supplied evidence."
        ):
            try:
                from app.ai_client import normalize_report, parse_model_response

                recovered = normalize_report(parse_model_response(item["raw_response"]))
                for source_key, item_key in {
                    "classification": "classification",
                    "confidence": "confidence",
                    "risk_adjustment": "risk_adjustment",
                    "summary": "summary",
                    "who": "who_summary",
                    "what": "what_summary",
                    "when": "when_summary",
                    "where": "where_summary",
                    "why": "why_summary",
                    "how": "how_summary",
                    "recommended_action": "recommended_action",
                }.items():
                    item[item_key] = recovered.get(source_key)
                item["next_steps"] = recovered.get("next_steps") or []
                item["threat_intel_analysis"] = recovered.get("threat_intel_analysis") or {}
            except (TypeError, ValueError):
                pass
        candidates.append(item)
    result["candidates"] = candidates
    result["votes"] = votes
    result["identities_revealed"] = True
    result.pop("id", None)
    return result


def list_ai_comparison_runs(conn, limit=50, case_uid=None):
    params = []
    where = ""
    if case_uid:
        where = "WHERE runs.case_uid = ?"
        params.append(case_uid)
    params.append(int(limit))
    rows = conn.execute(
        f"""
        SELECT runs.comparison_uid, runs.case_uid, runs.detection_id,
               runs.status, runs.candidate_count, runs.created_at,
               runs.completed_at, COUNT(votes.id) AS vote_count
        FROM ai_comparison_runs AS runs
        LEFT JOIN ai_comparison_votes AS votes ON votes.comparison_run_id = runs.id
        {where}
        GROUP BY runs.id
        ORDER BY runs.id DESC
        LIMIT ?
        """,
        tuple(params),
    ).fetchall()
    return [dict(row) for row in rows]


def vote_ai_comparison(conn, comparison_uid, analyst_name, selection, notes=""):
    run = conn.execute(
        "SELECT id FROM ai_comparison_runs WHERE comparison_uid = ?",
        (comparison_uid,),
    ).fetchone()
    if not run:
        return False
    existing_vote = conn.execute(
        "SELECT id FROM ai_comparison_votes WHERE comparison_run_id = ? LIMIT 1",
        (run["id"],),
    ).fetchone()
    if existing_vote:
        raise ValueError("This comparison has already been reviewed")
    allowed = {"A", "B", "C", "tie", "reject_all"}
    if selection not in allowed:
        raise ValueError("Selection must be A, B, C, tie, or reject_all")
    if selection in {"A", "B", "C"}:
        candidate = conn.execute(
            """
            SELECT id FROM ai_comparison_candidates
            WHERE comparison_run_id = ? AND anonymous_slot = ? AND status = 'complete'
            """,
            (run["id"], selection),
        ).fetchone()
        if not candidate:
            raise ValueError("The selected response is not available")
    conn.execute(
        """
        INSERT INTO ai_comparison_votes (
          comparison_run_id, analyst_name, selection, notes
        )
        VALUES (?, ?, ?, ?)
        """,
        (run["id"], analyst_name or "analyst", selection, notes),
    )
    conn.commit()
    return True


def ai_comparison_scorecard(conn):
    rows = conn.execute(
        """
        SELECT candidates.ai_profile_uid, candidates.model_provider,
               candidates.model_name, candidates.model_identity,
               COUNT(votes.id) AS wins
        FROM ai_comparison_votes AS votes
        JOIN ai_comparison_candidates AS candidates
          ON candidates.comparison_run_id = votes.comparison_run_id
         AND candidates.anonymous_slot = votes.selection
        WHERE votes.selection IN ('A', 'B', 'C')
        GROUP BY candidates.ai_profile_uid, candidates.model_identity
        ORDER BY wins DESC, candidates.model_identity ASC
        """
    ).fetchall()
    totals = conn.execute(
        """
        SELECT COUNT(*) AS votes,
               SUM(CASE WHEN selection = 'tie' THEN 1 ELSE 0 END) AS ties,
               SUM(CASE WHEN selection = 'reject_all' THEN 1 ELSE 0 END) AS rejected
        FROM ai_comparison_votes
        """
    ).fetchone()
    return {
        "models": [dict(row) for row in rows],
        "votes": int(totals["votes"] or 0),
        "ties": int(totals["ties"] or 0),
        "rejected": int(totals["rejected"] or 0),
    }


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


def delete_ai_profile(conn, uid):
    cur = conn.execute("DELETE FROM ai_profiles WHERE uid = ?", (uid,))
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
          protocol, signature, category, severity, priority, flow_id, community_id, pcap_point, raw_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            alert.get("community_id"),
            alert.get("pcap_point"),
            alert.get("raw_json"),
        ),
    )
    alert_id = cur.lastrowid
    event_uid = alert.get("event_uid") or stable_record_uid("SUR", alert_id, alert.get("timestamp"))
    cur.execute("UPDATE alerts SET event_uid = ? WHERE id = ?", (event_uid, alert_id))
    alert["event_uid"] = event_uid
    conn.commit()
    return alert_id


def insert_detection(conn, detection):
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO detections (
          first_alert_id, first_seen, last_seen, src_ip, dest_ip, src_port, dest_port,
          protocol, community_id, sensor_state, agreement_state, correlation_method,
          correlation_confidence, detection_type,
          alert_count, unique_dest_ports, unique_dest_hosts, time_window_seconds,
          mitre_id, mitre_name, python_initial_score, status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            detection.get("first_alert_id"),
            detection.get("first_seen"),
            detection.get("last_seen"),
            detection.get("src_ip"),
            detection.get("dest_ip"),
            detection.get("src_port"),
            detection.get("dest_port"),
            detection.get("protocol"),
            detection.get("community_id"),
            detection.get("sensor_state", "suricata_only"),
            detection.get("agreement_state", "single_sensor"),
            detection.get("correlation_method", "single_sensor"),
            detection.get("correlation_confidence", 0.5),
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
    detection_id = cur.lastrowid
    case_uid = detection.get("case_uid") or stable_record_uid(
        "CASE", detection_id, detection.get("first_seen")
    )
    cur.execute("UPDATE detections SET case_uid = ? WHERE id = ?", (case_uid, detection_id))
    detection["case_uid"] = case_uid
    conn.commit()
    return detection_id


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

    cur = conn.execute(
        """
        INSERT INTO ai_reports (
          detection_id, ai_profile_uid, model_provider, model_name, model_identity,
          model_endpoint, model_run_id, prompt_version, classification, confidence,
          risk_adjustment, reason, recommended_action, summary,
          who_summary, what_summary, when_summary, where_summary,
          why_summary, how_summary, next_steps_json, threat_intel_analysis_json,
          raw_response, elapsed_ms, prompt_sha256, prompt_chars
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            sqlite_value(report.get("summary")),
            sqlite_value(report.get("who")),
            sqlite_value(report.get("what")),
            sqlite_value(report.get("when")),
            sqlite_value(report.get("where")),
            sqlite_value(report.get("why")),
            sqlite_value(report.get("how")),
            sqlite_value(report.get("next_steps") or []),
            sqlite_value(report.get("threat_intel_analysis") or {}),
            sqlite_value(report.get("raw_response")),
            sqlite_int(report.get("elapsed_ms", 0)),
            sqlite_value(report.get("prompt_sha256")),
            sqlite_int(report.get("prompt_chars", 0)),
        ),
    )
    conn.commit()
    return cur.lastrowid


def insert_ai_assessment(conn, detection_id, report, assessment_type="initial", evidence_sources=None):
    cur = conn.execute(
        """
        INSERT INTO ai_assessments (
          detection_id, incident_evidence_id, assessment_type, provider,
          model_name, classification, confidence, risk_adjustment, reason,
          recommended_action, evidence_sources_json, response_time_ms,
          raw_response, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            detection_id,
            report.get("incident_evidence_id"),
            assessment_type,
            report.get("model_provider"),
            report.get("model_name") or "unknown",
            report.get("classification") or "Human Review Required",
            report.get("confidence") or "Low",
            int(report.get("risk_adjustment") or 0),
            report.get("reason"),
            report.get("recommended_action"),
            json.dumps(evidence_sources or {}, sort_keys=True),
            int(report.get("elapsed_ms") or 0),
            report.get("raw_response"),
            utc_now(),
        ),
    )
    conn.commit()
    return cur.lastrowid


def update_detection_python_score(conn, detection_id, score):
    conn.execute(
        "UPDATE detections SET python_initial_score = ? WHERE id = ?",
        (max(0, min(int(score), 90)), detection_id),
    )
    conn.commit()


def insert_score_breakdown(
    conn,
    detection_id,
    breakdown,
    ai_report_id=None,
    assessment_type="initial",
    llm_adjustment_raw=0,
    llm_adjustment_applied=0,
    provisional_score=None,
):
    python_score = max(0, min(int(breakdown.get("python_score") or 0), 90))
    provisional = max(
        0,
        min(
            100,
            int(provisional_score if provisional_score is not None else python_score + llm_adjustment_applied),
        ),
    )
    cur = conn.execute(
        """
        INSERT INTO score_breakdowns (
          detection_id, ai_report_id, assessment_type, sensor_severity,
          behavior_correlation, threat_intelligence, mitre_relevance,
          asset_direction, sensor_corroboration, python_score,
          llm_adjustment_raw, llm_adjustment_applied, provisional_score,
          forced_review, forced_review_reason, details_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            detection_id,
            ai_report_id,
            assessment_type,
            int(breakdown.get("sensor_severity") or 0),
            int(breakdown.get("behavior_correlation") or 0),
            int(breakdown.get("threat_intelligence") or 0),
            int(breakdown.get("mitre_relevance") or 0),
            int(breakdown.get("asset_direction") or 0),
            int(breakdown.get("sensor_corroboration") or 0),
            python_score,
            int(llm_adjustment_raw or 0),
            int(llm_adjustment_applied or 0),
            provisional,
            1 if breakdown.get("forced_review") else 0,
            breakdown.get("forced_review_reason"),
            json.dumps(breakdown.get("details") or {}, sort_keys=True),
        ),
    )
    conn.commit()
    return cur.lastrowid


def score_breakdowns_for_detection(conn, detection_id):
    rows = conn.execute(
        "SELECT * FROM score_breakdowns WHERE detection_id = ? ORDER BY id",
        (detection_id,),
    ).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        try:
            item["details"] = json.loads(item.pop("details_json") or "{}")
        except (TypeError, ValueError):
            item["details"] = {}
        result.append(item)
    return result


def insert_virustotal_verification(conn, detection_id, verification, ai_report_id=None, stage="initial"):
    cur = conn.execute(
        """
        INSERT INTO virustotal_verifications (
          detection_id, ai_report_id, assessment_stage, ip_address,
          request_state, verdict, interpretation, malicious_count,
          suspicious_count, cached, details_json, error, checked_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            detection_id,
            ai_report_id,
            stage,
            verification.get("indicator") or verification.get("ip_address"),
            verification.get("request_state") or "failed",
            verification.get("verdict") or "unknown",
            verification.get("interpretation") or "unavailable",
            int(verification.get("malicious_count") or 0),
            int(verification.get("suspicious_count") or 0),
            1 if verification.get("cached") else 0,
            json.dumps(verification.get("details") or {}, sort_keys=True),
            verification.get("error"),
            verification.get("checked_at") or utc_now(),
        ),
    )
    conn.commit()
    return cur.lastrowid


def virustotal_verifications_for_detection(conn, detection_id):
    rows = conn.execute(
        "SELECT * FROM virustotal_verifications WHERE detection_id = ? ORDER BY id",
        (detection_id,),
    ).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        try:
            item["details"] = json.loads(item.pop("details_json") or "{}")
        except (TypeError, ValueError):
            item["details"] = {}
        result.append(item)
    return result


def insert_incident_evidence(conn, evidence):
    now = utc_now()
    conn.execute(
        """
        INSERT INTO incident_evidence (
          detection_id, alert_id, incident_directory,
          incident_start_time, incident_end_time, window_start, window_end,
          incident_pcap_path, pcap_path, pcap_summary_path, zeek_logs_path,
          pcap_summary, evidence_manifest_path, status, error_message, capture_label,
          file_size_bytes, pcap_modified_at, summary_status,
          summary_packet_count, summary_error, display_filter, ai_sent,
          ai_model_run_id, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            evidence.get("detection_id"),
            evidence.get("alert_id"),
            evidence.get("incident_directory"),
            evidence.get("incident_start_time"),
            evidence.get("incident_end_time"),
            evidence.get("window_start") or evidence.get("incident_start_time"),
            evidence.get("window_end") or evidence.get("incident_end_time"),
            evidence.get("incident_pcap_path"),
            evidence.get("pcap_path") or evidence.get("incident_pcap_path"),
            evidence.get("pcap_summary_path"),
            evidence.get("zeek_logs_path"),
            evidence.get("pcap_summary"),
            evidence.get("evidence_manifest_path"),
            evidence.get("status") or evidence.get("summary_status") or "pending",
            evidence.get("error_message") or evidence.get("summary_error"),
            evidence.get("capture_label"),
            evidence.get("file_size_bytes"),
            evidence.get("pcap_modified_at"),
            evidence.get("summary_status"),
            evidence.get("summary_packet_count"),
            evidence.get("summary_error"),
            evidence.get("display_filter"),
            1 if evidence.get("ai_sent") else 0,
            evidence.get("ai_model_run_id"),
            evidence.get("updated_at") or now,
        ),
    )
    conn.commit()


def insert_zeek_event(conn, event):
    cur = conn.execute(
        """
        INSERT OR IGNORE INTO zeek_events (
          zeek_uid, log_type, timestamp, source_ip, source_port,
          destination_ip, destination_port, protocol, community_id, event_name, message,
          sub_message, actions_json, raw_json, ingested_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event.get("zeek_uid"),
            event.get("log_type"),
            event.get("timestamp"),
            event.get("source_ip"),
            event.get("source_port"),
            event.get("destination_ip"),
            event.get("destination_port"),
            event.get("protocol"),
            event.get("community_id"),
            event.get("event_name"),
            event.get("message"),
            event.get("sub_message"),
            json.dumps(event.get("actions") or [], sort_keys=True),
            json.dumps(event.get("raw_json") or {}, sort_keys=True),
            event.get("ingested_at") or utc_now(),
        ),
    )
    if cur.rowcount:
        event_id = cur.lastrowid
        event_uid = event.get("event_uid") or stable_record_uid(
            "ZEK", event_id, event.get("timestamp")
        )
        conn.execute("UPDATE zeek_events SET event_uid = ? WHERE id = ?", (event_uid, event_id))
        event["event_uid"] = event_uid
    conn.commit()
    return cur.rowcount


def zeek_event_id(conn, event):
    row = conn.execute(
        """
        SELECT id FROM zeek_events
        WHERE log_type = ? AND timestamp = ?
          AND COALESCE(zeek_uid, '') = COALESCE(?, '')
          AND event_name = ? AND message = ?
        ORDER BY id DESC LIMIT 1
        """,
        (
            event.get("log_type"),
            event.get("timestamp"),
            event.get("zeek_uid"),
            event.get("event_name"),
            event.get("message"),
        ),
    ).fetchone()
    return row["id"] if row else None


def zeek_flow_for_uid(conn, zeek_uid):
    if not zeek_uid:
        return None
    row = conn.execute(
        """
        SELECT source_ip, source_port, destination_ip, destination_port,
               protocol, community_id
        FROM zeek_events
        WHERE zeek_uid = ? AND log_type = 'conn'
        ORDER BY id DESC LIMIT 1
        """,
        (zeek_uid,),
    ).fetchone()
    return dict(row) if row else None


def insert_sensor_finding(conn, detection_id, finding):
    raw_event = finding.get("raw_event")
    if isinstance(raw_event, (dict, list)):
        raw_event = json.dumps(raw_event, sort_keys=True)
    cur = conn.execute(
        """
        INSERT OR IGNORE INTO sensor_findings (
          detection_id, sensor, sensor_event_id, finding_type, finding_name,
          severity, confidence, community_id, raw_event
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            detection_id,
            finding.get("sensor"),
            finding.get("sensor_event_id"),
            finding.get("finding_type"),
            finding.get("finding_name"),
            finding.get("severity"),
            finding.get("confidence"),
            finding.get("community_id"),
            raw_event,
        ),
    )
    conn.commit()
    return cur.rowcount > 0


def sensor_findings_for_detection(conn, detection_id):
    rows = conn.execute(
        """
        SELECT
          sensor_findings.*,
          COALESCE(alerts.timestamp, zeek_events.timestamp) AS finding_timestamp,
          COALESCE(alerts.src_ip, zeek_events.source_ip) AS source_ip,
          COALESCE(alerts.src_port, zeek_events.source_port) AS source_port,
          COALESCE(alerts.dest_ip, zeek_events.destination_ip) AS destination_ip,
          COALESCE(alerts.dest_port, zeek_events.destination_port) AS destination_port,
          COALESCE(alerts.protocol, zeek_events.protocol) AS protocol
          ,COALESCE(alerts.event_uid, zeek_events.event_uid) AS event_uid
        FROM sensor_findings
        LEFT JOIN alerts
          ON sensor_findings.sensor = 'suricata'
         AND alerts.id = sensor_findings.sensor_event_id
        LEFT JOIN zeek_events
          ON sensor_findings.sensor = 'zeek'
         AND zeek_events.id = sensor_findings.sensor_event_id
        WHERE sensor_findings.detection_id = ?
        ORDER BY COALESCE(alerts.timestamp, zeek_events.timestamp), sensor_findings.id
        """,
        (detection_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def sensor_finding_detection_id(conn, sensor, sensor_event_id):
    row = conn.execute(
        "SELECT detection_id FROM sensor_findings WHERE sensor = ? AND sensor_event_id = ?",
        (sensor, sensor_event_id),
    ).fetchone()
    return row["detection_id"] if row else None


def detection_by_id(conn, detection_id):
    row = conn.execute("SELECT * FROM detections WHERE id = ?", (detection_id,)).fetchone()
    return dict(row) if row else None


def detection_by_case_uid(conn, case_uid):
    row = conn.execute("SELECT * FROM detections WHERE case_uid = ?", (case_uid,)).fetchone()
    return dict(row) if row else None


def _event_time(value):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _event_endpoints(event):
    return (
        event.get("src_ip") or event.get("source_ip"),
        event.get("dest_ip") or event.get("destination_ip"),
        event.get("src_port") or event.get("source_port"),
        event.get("dest_port") or event.get("destination_port"),
    )


def _event_name(event):
    return str(
        event.get("signature")
        or event.get("event_name")
        or event.get("message")
        or ""
    ).strip().lower()


OBSERVABLE_KEYS = {
    "query",
    "host",
    "hostname",
    "server_name",
    "sni",
    "uri",
    "url",
    "md5",
    "sha1",
    "sha256",
    "ja3",
    "ja3s",
    "fingerprint",
    "certificate_fingerprint",
    "cert_chain_fps",
}


def _event_observables(event):
    observables = set()

    def collect(value, key=""):
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
            except (TypeError, ValueError, json.JSONDecodeError):
                parsed = None
            if isinstance(parsed, (dict, list)):
                collect(parsed, key)
                return
            if key in OBSERVABLE_KEYS:
                normalized = value.strip().lower()
                if len(normalized) >= 3:
                    observables.add(normalized)
            return
        if isinstance(value, dict):
            for child_key, child_value in value.items():
                collect(child_value, str(child_key).lower().replace(".", "_"))
            return
        if isinstance(value, (list, tuple, set)):
            for item in value:
                collect(item, key)
            return
        if value is not None and key in OBSERVABLE_KEYS:
            observables.add(str(value).strip().lower())

    collect(event)
    collect(event.get("raw_json"), "raw_json")
    collect(event.get("raw_event"), "raw_event")
    return observables


def _candidate_observables(conn, detection_ids):
    if not detection_ids:
        return {}
    placeholders = ",".join("?" for _ in detection_ids)
    rows = conn.execute(
        f"SELECT detection_id, raw_event FROM sensor_findings WHERE detection_id IN ({placeholders})",
        tuple(detection_ids),
    ).fetchall()
    by_detection = {detection_id: set() for detection_id in detection_ids}
    for row in rows:
        by_detection[row["detection_id"]].update(_event_observables({"raw_event": row["raw_event"]}))
    return by_detection


def _same_sensor_behavior_match(event, candidate):
    src, dst, _src_port, _dst_port = _event_endpoints(event)
    if not src or src != candidate.get("src_ip"):
        return False
    incoming_type = str(event.get("detection_type") or "unknown").lower()
    candidate_type = str(candidate.get("detection_type") or "unknown").lower()
    if incoming_type != candidate_type:
        return False
    protocol = str(event.get("protocol") or "").lower()
    candidate_protocol = str(candidate.get("protocol") or "").lower()
    if protocol and candidate_protocol and protocol != candidate_protocol:
        return False
    if incoming_type == "port_scan":
        return True
    if incoming_type in {"dns_tunneling", "beaconing", "brute_force"}:
        return bool(dst and dst == candidate.get("dest_ip"))
    return bool(dst and dst == candidate.get("dest_ip") and _event_name(event) == str(candidate.get("finding_name") or "").lower())


def find_correlated_detection(
    conn,
    event,
    sensor,
    tolerance_seconds=10,
    same_sensor_window_seconds=300,
):
    community_id = str(event.get("community_id") or "").strip()
    if community_id:
        row = conn.execute(
            """
            SELECT detections.*
            FROM detections
            JOIN sensor_findings ON sensor_findings.detection_id = detections.id
            WHERE detections.community_id = ? AND sensor_findings.sensor != ?
            ORDER BY detections.id DESC LIMIT 1
            """,
            (community_id, sensor),
        ).fetchone()
        if row:
            return dict(row), "community_id", 1.0

        row = conn.execute(
            """
            SELECT detections.*
            FROM detections
            JOIN sensor_findings ON sensor_findings.detection_id = detections.id
            WHERE detections.community_id = ? AND sensor_findings.sensor = ?
            ORDER BY detections.id DESC LIMIT 1
            """,
            (community_id, sensor),
        ).fetchone()
        if row:
            return dict(row), "community_id_same_sensor", 0.95

    zeek_uid = str(event.get("zeek_uid") or "").strip()
    if sensor == "zeek" and zeek_uid:
        row = conn.execute(
            """
            SELECT detections.*
            FROM detections
            JOIN sensor_findings ON sensor_findings.detection_id = detections.id
            JOIN zeek_events ON sensor_findings.sensor = 'zeek'
                            AND sensor_findings.sensor_event_id = zeek_events.id
            WHERE zeek_events.zeek_uid = ?
            ORDER BY detections.id DESC LIMIT 1
            """,
            (zeek_uid,),
        ).fetchone()
        if row:
            return dict(row), "zeek_uid", 0.95

    candidates = conn.execute(
        """
        SELECT DISTINCT detections.*
        FROM detections
        JOIN sensor_findings ON sensor_findings.detection_id = detections.id
        WHERE sensor_findings.sensor != ?
        ORDER BY detections.id DESC LIMIT 250
        """,
        (sensor,),
    ).fetchall()
    event_time = _event_time(event.get("timestamp"))
    src, dst, src_port, dst_port = _event_endpoints(event)
    protocol = str(event.get("protocol") or "").lower()
    for row in candidates:
        candidate = dict(row)
        candidate_time = _event_time(candidate.get("last_seen") or candidate.get("first_seen"))
        if event_time and candidate_time and abs((event_time - candidate_time).total_seconds()) > tolerance_seconds:
            continue
        direct = src == candidate.get("src_ip") and dst == candidate.get("dest_ip")
        reverse = src == candidate.get("dest_ip") and dst == candidate.get("src_ip")
        if not (direct or reverse):
            continue
        candidate_protocol = str(candidate.get("protocol") or "").lower()
        if protocol and candidate_protocol and protocol != candidate_protocol:
            continue
        if src_port is not None and dst_port is not None:
            candidate_ports = (candidate.get("src_port"), candidate.get("dest_port"))
            if direct and (src_port, dst_port) != candidate_ports:
                continue
            if reverse and (dst_port, src_port) != candidate_ports:
                continue
        return candidate, "flow_time", 0.85

    incoming_observables = _event_observables(event)
    if incoming_observables:
        observable_candidates = conn.execute(
            """
            SELECT DISTINCT detections.*
            FROM detections
            JOIN sensor_findings ON sensor_findings.detection_id = detections.id
            ORDER BY detections.id DESC LIMIT 250
            """
        ).fetchall()
        candidate_items = [dict(row) for row in observable_candidates]
        observable_map = _candidate_observables(
            conn, [candidate["id"] for candidate in candidate_items]
        )
        incoming_type = str(event.get("detection_type") or "unknown").lower()
        for candidate in candidate_items:
            candidate_time = _event_time(candidate.get("last_seen") or candidate.get("first_seen"))
            if event_time and candidate_time:
                elapsed = abs((event_time - candidate_time).total_seconds())
                if elapsed > same_sensor_window_seconds:
                    continue
            candidate_type = str(candidate.get("detection_type") or "unknown").lower()
            if incoming_type != candidate_type and "unknown" not in {incoming_type, candidate_type}:
                continue
            candidate_endpoints = {candidate.get("src_ip"), candidate.get("dest_ip")}
            if src not in candidate_endpoints and dst not in candidate_endpoints:
                continue
            if incoming_observables & observable_map.get(candidate["id"], set()):
                return candidate, "shared_observable", 0.82

    same_sensor_candidates = conn.execute(
        """
        SELECT detections.*, sensor_findings.finding_name
        FROM detections
        JOIN sensor_findings ON sensor_findings.detection_id = detections.id
        WHERE sensor_findings.sensor = ?
        ORDER BY detections.id DESC LIMIT 250
        """,
        (sensor,),
    ).fetchall()
    for row in same_sensor_candidates:
        candidate = dict(row)
        candidate_time = _event_time(candidate.get("last_seen") or candidate.get("first_seen"))
        if event_time and candidate_time:
            elapsed = (event_time - candidate_time).total_seconds()
            if elapsed < 0 or elapsed > same_sensor_window_seconds:
                continue
        if _same_sensor_behavior_match(event, candidate):
            return candidate, "same_sensor_behavior", 0.78
    return None, "none", 0.0


def fuse_detection(conn, detection_id, event, correlation_method, correlation_confidence):
    detection = detection_by_id(conn, detection_id)
    if not detection:
        return None
    score = min(90, int(detection.get("python_initial_score") or 0))
    finding_rows = conn.execute(
        """
        SELECT sensor_findings.sensor, sensor_findings.finding_name,
               COALESCE(alerts.timestamp, zeek_events.timestamp, sensor_findings.created_at) AS finding_time,
               COALESCE(alerts.src_ip, zeek_events.source_ip) AS src_ip,
               COALESCE(alerts.dest_ip, zeek_events.destination_ip) AS dest_ip,
               COALESCE(alerts.dest_port, zeek_events.destination_port) AS dest_port
        FROM sensor_findings
        LEFT JOIN alerts ON sensor_findings.sensor = 'suricata'
                        AND alerts.id = sensor_findings.sensor_event_id
        LEFT JOIN zeek_events ON sensor_findings.sensor = 'zeek'
                            AND zeek_events.id = sensor_findings.sensor_event_id
        WHERE sensor_findings.detection_id = ?
        ORDER BY finding_time, sensor_findings.id
        """,
        (detection_id,),
    ).fetchall()
    finding_count = len(finding_rows)
    sensors = {row["sensor"] for row in finding_rows}
    first_seen = detection.get("first_seen") or event.get("timestamp")
    last_seen = event.get("timestamp") or detection.get("last_seen")
    first_dt = _event_time(first_seen)
    event_dt = _event_time(event.get("timestamp"))
    if first_dt and event_dt:
        first_seen = min(first_dt, event_dt).isoformat()
        last_seen = max(_event_time(detection.get("last_seen")) or first_dt, event_dt).isoformat()
    finding_times = [_event_time(row["finding_time"]) for row in finding_rows]
    finding_times = [value for value in finding_times if value]
    if finding_times:
        first_seen = min(finding_times).isoformat()
        last_seen = max(finding_times).isoformat()
    unique_ports = {row["dest_port"] for row in finding_rows if row["dest_port"] is not None}
    unique_hosts = {row["dest_ip"] for row in finding_rows if row["dest_ip"]}
    window_seconds = 0
    if finding_times:
        window_seconds = int((max(finding_times) - min(finding_times)).total_seconds())
    existing_type = str(detection.get("detection_type") or "unknown")
    incoming_type = str(event.get("detection_type") or "unknown")
    multi_sensor = len(sensors) > 1
    if multi_sensor:
        agreement_state = "supporting" if existing_type == incoming_type or "unknown" in {existing_type, incoming_type} else "partial"
        sensor_state = "multi_sensor"
    else:
        agreement_state = "repeated" if finding_count > 1 else "single_sensor"
        sensor_state = f"{next(iter(sensors), 'suricata')}_only"
    existing_confidence = float(detection.get("correlation_confidence") or 0)
    if existing_confidence > float(correlation_confidence or 0):
        correlation_confidence = existing_confidence
        correlation_method = detection.get("correlation_method") or correlation_method
    conn.execute(
        """
        UPDATE detections
        SET first_seen = ?, last_seen = ?,
            first_alert_id = COALESCE(first_alert_id, ?),
            community_id = COALESCE(community_id, ?),
            sensor_state = ?,
            agreement_state = ?, correlation_method = ?,
            correlation_confidence = ?, python_initial_score = ?,
            alert_count = ?, unique_dest_ports = ?, unique_dest_hosts = ?,
            time_window_seconds = ?, status = ?
        WHERE id = ?
        """,
        (
            first_seen,
            last_seen,
            event.get("alert_id"),
            event.get("community_id"),
            sensor_state,
            agreement_state,
            correlation_method,
            correlation_confidence,
            score,
            finding_count,
            len(unique_ports),
            len(unique_hosts),
            window_seconds,
            "correlated" if multi_sensor else "developing",
            detection_id,
        ),
    )
    conn.commit()
    return detection_by_id(conn, detection_id)


def get_zeek_checkpoint(conn, log_type):
    row = conn.execute(
        "SELECT log_type, path, inode, offset, updated_at FROM zeek_ingest_checkpoints WHERE log_type = ?",
        (log_type,),
    ).fetchone()
    return dict(row) if row else None


def upsert_zeek_checkpoint(conn, log_type, path, inode, offset):
    conn.execute(
        """
        INSERT INTO zeek_ingest_checkpoints (log_type, path, inode, offset, updated_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(log_type) DO UPDATE SET
          path = excluded.path,
          inode = excluded.inode,
          offset = excluded.offset,
          updated_at = excluded.updated_at
        """,
        (log_type, str(path), int(inode or 0), int(offset or 0), utc_now()),
    )
    conn.commit()


def latest_zeek_events(conn, limit=50, log_type=None):
    params = []
    where = ""
    if log_type:
        where = "WHERE zeek_events.log_type = ?"
        params.append(log_type)
    params.append(limit)
    rows = conn.execute(
        f"""
        SELECT zeek_events.*, sensor_findings.detection_id, detections.case_uid
        FROM zeek_events
        LEFT JOIN sensor_findings
          ON sensor_findings.sensor = 'zeek'
         AND sensor_findings.sensor_event_id = zeek_events.id
        LEFT JOIN detections ON detections.id = sensor_findings.detection_id
        {where}
        ORDER BY zeek_events.id DESC
        LIMIT ?
        """,
        params,
    ).fetchall()
    return [dict(row) for row in rows]


def zeek_event_counts(conn):
    rows = conn.execute(
        """
        SELECT log_type, COUNT(*) AS count
        FROM zeek_events
        GROUP BY log_type
        ORDER BY count DESC
        """
    ).fetchall()
    return {row["log_type"]: row["count"] for row in rows}


def _zeek_raw(row):
    try:
        return json.loads(row["raw_json"] or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}


def _counter_rows(counter, name, limit=8):
    return [
        {name: value, "count": count}
        for value, count in counter.most_common(limit)
        if value not in (None, "")
    ]


def zeek_telemetry_summary(conn, limit=50):
    """Summarize stored Zeek metadata and ingest checkpoints for the dashboard."""
    limit = max(1, min(int(limit or 50), 200))
    counts = zeek_event_counts(conn)
    total_events = sum(counts.values())
    bounds = conn.execute(
        "SELECT MIN(timestamp) AS first_event, MAX(timestamp) AS last_event FROM zeek_events"
    ).fetchone()
    activity = conn.execute(
        """
        SELECT substr(timestamp, 1, 13) AS hour, COUNT(*) AS count
        FROM zeek_events
        GROUP BY substr(timestamp, 1, 13)
        ORDER BY hour DESC
        LIMIT 12
        """
    ).fetchall()
    checkpoints = conn.execute(
        """
        SELECT log_type, path, inode, offset, updated_at
        FROM zeek_ingest_checkpoints
        ORDER BY log_type
        """
    ).fetchall()

    tls_versions = Counter()
    tls_sni = Counter()
    tls_validation = Counter()
    tls_rows = []
    for row in conn.execute(
        "SELECT * FROM zeek_events WHERE log_type = 'ssl' ORDER BY id DESC LIMIT 1000"
    ).fetchall():
        raw = _zeek_raw(row)
        tls_versions[raw.get("version") or "unknown"] += 1
        if raw.get("server_name"):
            tls_sni[raw["server_name"]] += 1
        tls_validation[raw.get("validation_status") or "not recorded"] += 1
        if len(tls_rows) < min(limit, 25):
            tls_rows.append(
                {
                    "id": row["id"],
                    "event_uid": row["event_uid"],
                    "timestamp": row["timestamp"],
                    "source_ip": row["source_ip"],
                    "source_port": row["source_port"],
                    "destination_ip": row["destination_ip"],
                    "destination_port": row["destination_port"],
                    "server_name": raw.get("server_name"),
                    "version": raw.get("version"),
                    "cipher": raw.get("cipher"),
                    "validation_status": raw.get("validation_status"),
                    "sni_matches_cert": raw.get("sni_matches_cert"),
                    "established": raw.get("established"),
                    "resumed": raw.get("resumed"),
                }
            )

    file_mimes = Counter()
    file_sources = Counter()
    file_rows = []
    observed_bytes = 0
    complete_file_observations = 0
    for row in conn.execute(
        "SELECT * FROM zeek_events WHERE log_type = 'files' ORDER BY id DESC LIMIT 1000"
    ).fetchall():
        raw = _zeek_raw(row)
        seen_bytes = int(raw.get("seen_bytes") or 0)
        missing_bytes = int(raw.get("missing_bytes") or 0)
        observed_bytes += seen_bytes
        if missing_bytes == 0:
            complete_file_observations += 1
        file_mimes[raw.get("mime_type") or "unknown"] += 1
        file_sources[raw.get("source") or "unknown"] += 1
        if len(file_rows) < min(limit, 25):
            file_rows.append(
                {
                    "id": row["id"],
                    "event_uid": row["event_uid"],
                    "timestamp": row["timestamp"],
                    "source_ip": row["source_ip"],
                    "destination_ip": row["destination_ip"],
                    "source": raw.get("source"),
                    "mime_type": raw.get("mime_type"),
                    "filename": raw.get("filename"),
                    "seen_bytes": seen_bytes,
                    "missing_bytes": missing_bytes,
                    "md5": raw.get("md5"),
                    "sha1": raw.get("sha1"),
                    "fuid": raw.get("fuid"),
                }
            )

    dns_queries = Counter()
    dns_types = Counter()
    dns_rcodes = Counter()
    for row in conn.execute(
        """
        SELECT raw_json, message
        FROM zeek_events
        WHERE log_type = 'dns'
        ORDER BY id DESC
        LIMIT 5000
        """
    ).fetchall():
        raw = _zeek_raw(row)
        query = raw.get("query") or row["message"]
        if query and query != "DNS event observed":
            dns_queries[query] += 1
        dns_types[raw.get("qtype_name") or "unknown"] += 1
        dns_rcodes[raw.get("rcode_name") or "unknown"] += 1

    http_hosts = Counter()
    http_statuses = Counter()
    http_methods = Counter()
    for row in conn.execute(
        "SELECT raw_json FROM zeek_events WHERE log_type = 'http' ORDER BY id DESC LIMIT 1000"
    ).fetchall():
        raw = _zeek_raw(row)
        http_hosts[raw.get("host") or "unknown"] += 1
        http_statuses[str(raw.get("status_code") or "unknown")] += 1
        http_methods[raw.get("method") or "unknown"] += 1

    recent_events = latest_zeek_events(conn, limit)
    return {
        "total_events": total_events,
        "active_log_types": len(counts),
        "first_event": bounds["first_event"] if bounds else None,
        "last_event": bounds["last_event"] if bounds else None,
        "event_counts": counts,
        "activity": [dict(row) for row in reversed(activity)],
        "checkpoints": [dict(row) for row in checkpoints],
        "tls": {
            "count": counts.get("ssl", 0),
            "versions": _counter_rows(tls_versions, "version"),
            "top_server_names": _counter_rows(tls_sni, "server_name"),
            "validation": _counter_rows(tls_validation, "status"),
            "recent": tls_rows,
        },
        "files": {
            "count": counts.get("files", 0),
            "observed_bytes_recent": observed_bytes,
            "complete_observations_recent": complete_file_observations,
            "mime_types": _counter_rows(file_mimes, "mime_type"),
            "sources": _counter_rows(file_sources, "source"),
            "recent": file_rows,
        },
        "dns": {
            "count": counts.get("dns", 0),
            "top_queries": _counter_rows(dns_queries, "query", limit=10),
            "query_types": _counter_rows(dns_types, "query_type"),
            "response_codes": _counter_rows(dns_rcodes, "response_code"),
        },
        "http": {
            "count": counts.get("http", 0),
            "top_hosts": _counter_rows(http_hosts, "host"),
            "methods": _counter_rows(http_methods, "method"),
            "statuses": _counter_rows(http_statuses, "status"),
        },
        "recent_events": recent_events,
    }


def zeek_context_for_detection(conn, detection_id, seconds=120, limit=100):
    detection = conn.execute(
        """
        SELECT id, first_seen, last_seen, src_ip, dest_ip, community_id,
               detection_type, alert_count, time_window_seconds
        FROM detections WHERE id = ?
        """,
        (detection_id,),
    ).fetchone()
    if not detection:
        return {"detection_id": detection_id, "items": []}
    start_text = detection["first_seen"] or detection["last_seen"]
    end_text = detection["last_seen"] or detection["first_seen"]
    if not start_text:
        return {"detection_id": detection_id, "items": []}
    try:
        start = datetime.fromisoformat(str(start_text).replace("Z", "+00:00")) - timedelta(seconds=seconds)
        end = datetime.fromisoformat(str(end_text).replace("Z", "+00:00")) + timedelta(seconds=seconds)
        start_value = start.isoformat()
        end_value = end.isoformat()
    except ValueError:
        start_value = start_text
        end_value = end_text or start_text
    related_uids = [
        row["zeek_uid"]
        for row in conn.execute(
            """
            SELECT DISTINCT zeek_events.zeek_uid
            FROM sensor_findings
            JOIN zeek_events ON sensor_findings.sensor = 'zeek'
                            AND sensor_findings.sensor_event_id = zeek_events.id
            WHERE sensor_findings.detection_id = ? AND zeek_events.zeek_uid IS NOT NULL
            """,
            (detection_id,),
        ).fetchall()
    ]
    repeated_type = detection["detection_type"] in {
        "port_scan", "dns_tunneling", "beaconing", "brute_force"
    }
    rows = conn.execute(
        """
        SELECT *
        FROM zeek_events
        WHERE timestamp BETWEEN ? AND ?
          AND (
            (? != '' AND community_id = ?)
            OR (source_ip = ? AND destination_ip = ?)
            OR (source_ip = ? AND destination_ip = ?)
            OR (? = 1 AND source_ip = ?)
          )
        ORDER BY timestamp ASC, id ASC
        LIMIT ?
        """,
        (
            start_value,
            end_value,
            detection["community_id"] or "",
            detection["community_id"] or "",
            detection["src_ip"],
            detection["dest_ip"],
            detection["dest_ip"],
            detection["src_ip"],
            int(repeated_type),
            detection["src_ip"],
            limit,
        ),
    ).fetchall()
    items = [dict(row) for row in rows]
    if related_uids:
        uid_rows = conn.execute(
            f"""
            SELECT * FROM zeek_events
            WHERE timestamp BETWEEN ? AND ?
              AND zeek_uid IN ({','.join('?' for _ in related_uids)})
            ORDER BY timestamp ASC, id ASC LIMIT ?
            """,
            (start_value, end_value, *related_uids, limit),
        ).fetchall()
        by_id = {item["id"]: item for item in items}
        by_id.update({row["id"]: dict(row) for row in uid_rows})
        items = sorted(by_id.values(), key=lambda item: (item.get("timestamp") or "", item["id"]))[:limit]

    log_counts = {}
    domains = set()
    server_names = set()
    http_hosts = set()
    total_orig_bytes = 0
    total_resp_bytes = 0
    total_duration = 0.0
    event_times = []
    for item in items:
        log_type = item.get("log_type") or "unknown"
        log_counts[log_type] = log_counts.get(log_type, 0) + 1
        try:
            raw = json.loads(item.get("raw_json") or "{}")
        except (TypeError, json.JSONDecodeError):
            raw = {}
        query = raw.get("query")
        server_name = raw.get("server_name")
        host = raw.get("host")
        if query:
            domains.add(str(query))
        if server_name:
            server_names.add(str(server_name))
        if host:
            http_hosts.add(str(host))
        total_orig_bytes += int(raw.get("orig_bytes") or raw.get("orig_ip_bytes") or 0)
        total_resp_bytes += int(raw.get("resp_bytes") or raw.get("resp_ip_bytes") or 0)
        try:
            total_duration += float(raw.get("duration") or 0)
        except (TypeError, ValueError):
            pass
        parsed_time = _event_time(item.get("timestamp"))
        if parsed_time:
            event_times.append(parsed_time)
    intervals = [
        round((current - previous).total_seconds(), 3)
        for previous, current in zip(event_times, event_times[1:])
    ]
    average_interval = round(sum(intervals) / len(intervals), 3) if intervals else None
    periodicity = None
    if len(intervals) >= 3 and average_interval and average_interval > 0:
        spread = max(intervals) - min(intervals)
        periodicity = "regular" if spread / average_interval <= 0.25 else "irregular"
    return {
        "detection_id": detection_id,
        "window_start": start_value,
        "window_end": end_value,
        "summary": {
            "event_count": len(items),
            "log_counts": log_counts,
            "first_seen": items[0].get("timestamp") if items else None,
            "last_seen": items[-1].get("timestamp") if items else None,
            "dns_queries": sorted(domains)[:20],
            "tls_server_names": sorted(server_names)[:20],
            "http_hosts": sorted(http_hosts)[:20],
            "originator_bytes": total_orig_bytes,
            "responder_bytes": total_resp_bytes,
            "connection_duration_seconds": round(total_duration, 3),
            "average_interval_seconds": average_interval,
            "periodicity": periodicity,
            "related_zeek_uids": related_uids,
            "case_finding_count": int(detection["alert_count"] or 0),
            "case_window_seconds": int(detection["time_window_seconds"] or 0),
        },
        "items": items,
    }


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
          detection_id, ip_address, direction, zone, reason, firewall_rule, timeout_seconds,
          status, response_status, response_time_ms, created_at, expires_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            block.get("detection_id"),
            normalize_ip(block.get("ip_address")),
            block.get("direction"),
            block.get("zone"),
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
          (
            SELECT COUNT(*)
            FROM allowlist
            WHERE allowlist.ip_address = responses.target_ip
              AND allowlist.status = 'active'
          ) AS active_allowlist_count,
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
        "ai_comparison_votes",
        "ai_comparison_candidates",
        "ai_comparison_runs",
        "alerts",
        "detections",
        "ai_reports",
        "responses",
        "incident_evidence",
        "analyst_reviews",
        "tuning_labels",
        "app_events",
        "threat_intel_lookups",
        "threat_intel_usage",
        "notification_events",
        "zeek_events",
        "zeek_ingest_checkpoints",
        "ai_assessments",
        "sensor_findings",
        "score_breakdowns",
        "virustotal_verifications",
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
          detections.case_uid,
          detections.detection_type,
          responses.final_score,
          responses.final_classification
        FROM alerts
        LEFT JOIN detections ON detections.first_alert_id = alerts.id
        LEFT JOIN responses ON responses.id = (
          SELECT MAX(r2.id) FROM responses r2 WHERE r2.detection_id = detections.id
        )
        ORDER BY alerts.id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [dict(row) for row in rows]


def latest_sensor_alerts(conn, limit=50, sensor_filter=None):
    normalized_filter = str(sensor_filter or "all").strip().lower()
    filter_sql = ""
    if normalized_filter == "suricata":
        filter_sql = """
        WHERE EXISTS (
          SELECT 1 FROM sensor_findings sf
          WHERE sf.detection_id = detections.id AND sf.sensor = 'suricata'
        )
        """
    elif normalized_filter == "zeek":
        filter_sql = """
        WHERE EXISTS (
          SELECT 1 FROM sensor_findings sf
          WHERE sf.detection_id = detections.id AND sf.sensor = 'zeek'
        )
        """
    elif normalized_filter in {"both", "multi_sensor"}:
        filter_sql = """
        WHERE EXISTS (
          SELECT 1 FROM sensor_findings sf
          WHERE sf.detection_id = detections.id AND sf.sensor = 'suricata'
        )
        AND EXISTS (
          SELECT 1 FROM sensor_findings sf
          WHERE sf.detection_id = detections.id AND sf.sensor = 'zeek'
        )
        """
    rows = conn.execute(
        f"""
        SELECT
          detections.id AS detection_id,
          detections.case_uid,
          COALESCE(alerts.event_uid, (
            SELECT zeek_events.event_uid
            FROM sensor_findings
            JOIN zeek_events ON sensor_findings.sensor = 'zeek'
                            AND zeek_events.id = sensor_findings.sensor_event_id
            WHERE sensor_findings.detection_id = detections.id
            ORDER BY sensor_findings.id LIMIT 1
          )) AS event_uid,
          COALESCE(alerts.timestamp, detections.first_seen) AS timestamp,
          COALESCE(alerts.src_ip, detections.src_ip) AS src_ip,
          COALESCE(alerts.dest_ip, detections.dest_ip) AS dest_ip,
          COALESCE(alerts.src_port, detections.src_port) AS src_port,
          COALESCE(alerts.dest_port, detections.dest_port) AS dest_port,
          COALESCE(alerts.protocol, detections.protocol) AS protocol,
          COALESCE(alerts.signature, (
            SELECT finding_name
            FROM sensor_findings
            WHERE sensor_findings.detection_id = detections.id
            ORDER BY sensor_findings.id
            LIMIT 1
          ), 'Network detection') AS signature,
          alerts.category,
          alerts.priority,
          detections.detection_type,
          detections.sensor_state,
          detections.agreement_state,
          detections.correlation_method,
          detections.correlation_confidence,
          detections.community_id,
          responses.final_score,
          responses.final_classification,
          responses.final_action
        FROM detections
        LEFT JOIN alerts ON alerts.id = detections.first_alert_id
        LEFT JOIN responses ON responses.id = (
          SELECT MAX(r2.id) FROM responses r2 WHERE r2.detection_id = detections.id
        )
        {filter_sql}
        ORDER BY detections.id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    results = []
    for row in rows:
        item = dict(row)
        item["sensor_findings"] = sensor_findings_for_detection(conn, item["detection_id"])
        results.append(item)
    return results


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
          ai_reports.summary,
          ai_reports.who_summary,
          ai_reports.what_summary,
          ai_reports.when_summary,
          ai_reports.where_summary,
          ai_reports.why_summary,
          ai_reports.how_summary,
          ai_reports.next_steps_json,
          ai_reports.elapsed_ms,
          ai_reports.prompt_sha256,
          ai_reports.prompt_chars,
          ai_reports.pcap_summary_sha256,
          ai_reports.pcap_summary_chars,
          ai_reports.pcap_summary_included,
          ai_reports.created_at,
          detections.case_uid,
          detections.detection_type,
          detections.python_initial_score,
          COALESCE(alerts.timestamp, detections.first_seen) AS timestamp,
          COALESCE(alerts.src_ip, detections.src_ip) AS src_ip,
          COALESCE(alerts.dest_ip, detections.dest_ip) AS dest_ip,
          COALESCE(alerts.signature, (
            SELECT finding_name FROM sensor_findings
            WHERE detection_id = detections.id ORDER BY id LIMIT 1
          )) AS signature,
          detections.sensor_state,
          detections.agreement_state
        FROM ai_reports
        LEFT JOIN detections ON detections.id = ai_reports.detection_id
        LEFT JOIN alerts ON alerts.id = detections.first_alert_id
        WHERE ai_reports.id = (
          SELECT MAX(a2.id) FROM ai_reports a2 WHERE a2.detection_id = ai_reports.detection_id
        )
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
    alert_id=None,
    detection_id=None,
):
    conn.execute(
        """
        INSERT INTO threat_intel_lookups (
          alert_id, detection_id, indicator, indicator_type, source,
          lookup_result, malicious_count, suspicious_count, reputation,
          lookup_time, cached, raw_response
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            alert_id,
            detection_id,
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


def record_threat_intel_usage(
    conn,
    detection_id,
    alert_id,
    indicator,
    indicator_type,
    source,
    stage,
    details=None,
):
    conn.execute(
        """
        INSERT INTO threat_intel_usage (
          detection_id, alert_id, indicator, indicator_type, source,
          stage, matched, details_json, used_at
        ) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
        ON CONFLICT(detection_id, indicator, indicator_type, source, stage)
        DO UPDATE SET
          alert_id = excluded.alert_id,
          matched = 1,
          details_json = excluded.details_json,
          used_at = excluded.used_at
        """,
        (
            detection_id,
            alert_id,
            indicator,
            indicator_type,
            source,
            stage,
            json.dumps(details or {}, sort_keys=True),
            utc_now(),
        ),
    )
    conn.commit()


def threat_intel_usage_summary(conn):
    rows = conn.execute(
        """
        SELECT source, stage, COUNT(*) AS usage_count, MAX(used_at) AS last_used
        FROM threat_intel_usage
        GROUP BY source, stage
        ORDER BY source, stage
        """
    ).fetchall()
    summary = {}
    for row in rows:
        item = dict(row)
        source = item.pop("source")
        summary.setdefault(source, {"usage_count": 0, "last_used": None, "stages": {}})
        summary[source]["usage_count"] += int(item.get("usage_count") or 0)
        if not summary[source]["last_used"] or str(item.get("last_used") or "") > summary[source]["last_used"]:
            summary[source]["last_used"] = item.get("last_used")
        summary[source]["stages"][item["stage"]] = {
            "usage_count": int(item.get("usage_count") or 0),
            "last_used": item.get("last_used"),
        }
    return summary


def replace_threat_intel_indicators(conn, source, indicators):
    imported_at = utc_now()
    rows = []
    for item in indicators:
        indicator = str(item.get("indicator") or "").strip()
        indicator_type = str(item.get("indicator_type") or "").strip().lower()
        if not indicator or not indicator_type:
            continue
        rows.append(
            (
                indicator,
                indicator_type,
                source,
                item.get("category"),
                item.get("malware_family"),
                item.get("confidence"),
                item.get("first_seen"),
                item.get("last_seen"),
                item.get("expires_at"),
                item.get("source_reference"),
                json.dumps(item.get("raw_data"), sort_keys=True)
                if isinstance(item.get("raw_data"), (dict, list))
                else item.get("raw_data"),
                imported_at,
            )
        )
    with conn:
        conn.execute("DELETE FROM threat_intel_indicators WHERE source = ?", (source,))
        conn.executemany(
            """
            INSERT OR REPLACE INTO threat_intel_indicators (
              indicator, indicator_type, source, category, malware_family,
              confidence, first_seen, last_seen, expires_at, source_reference,
              raw_data, imported_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        indicator_count = conn.execute(
            "SELECT COUNT(*) FROM threat_intel_indicators WHERE source = ?",
            (source,),
        ).fetchone()[0]
        conn.execute(
            """
            INSERT INTO threat_intel_sources (
              source, status, indicator_count, last_attempt, last_success, last_error, updated_at
            ) VALUES (?, 'ready', ?, ?, ?, '', ?)
            ON CONFLICT(source) DO UPDATE SET
              status = 'ready', indicator_count = excluded.indicator_count,
              last_attempt = excluded.last_attempt, last_success = excluded.last_success,
              last_error = '', updated_at = excluded.updated_at
            """,
            (source, indicator_count, imported_at, imported_at, imported_at),
        )
    return indicator_count


def update_threat_intel_source(conn, source, status, error=""):
    now = utc_now()
    conn.execute(
        """
        INSERT INTO threat_intel_sources (source, status, last_attempt, last_error, updated_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(source) DO UPDATE SET
          status = excluded.status, last_attempt = excluded.last_attempt,
          last_error = excluded.last_error, updated_at = excluded.updated_at
        """,
        (source, status, now, error, now),
    )
    conn.commit()


def threat_intel_source_rows(conn):
    rows = conn.execute("SELECT * FROM threat_intel_sources ORDER BY source").fetchall()
    return {row["source"]: dict(row) for row in rows}


def threat_intel_matches(conn, indicator, indicator_type="ip"):
    value = str(indicator or "").strip()
    if not value:
        return []
    rows = conn.execute(
        """
        SELECT indicator, indicator_type, source, category, malware_family,
               confidence, first_seen, last_seen, expires_at, source_reference,
               imported_at
        FROM threat_intel_indicators
        WHERE lower(indicator) = lower(?)
        ORDER BY confidence DESC, source
        """,
        (value,),
    ).fetchall()
    matches = [dict(row) for row in rows]
    if indicator_type == "ip":
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            address = None
        if address:
            cidr_rows = conn.execute(
                """
                SELECT indicator, indicator_type, source, category, malware_family,
                       confidence, first_seen, last_seen, expires_at, source_reference,
                       imported_at
                FROM threat_intel_indicators
                WHERE indicator_type = 'cidr'
                """
            ).fetchall()
            for row in cidr_rows:
                try:
                    if address in ipaddress.ip_network(row["indicator"], strict=False):
                        matches.append(dict(row))
                except ValueError:
                    continue
    return matches


def threat_intel_provider_results(conn, indicator, providers, indicator_type="ip"):
    matches = threat_intel_matches(conn, indicator, indicator_type)
    by_source = {}
    for match in matches:
        by_source.setdefault(match["source"], []).append(match)
    results = []
    for provider in providers:
        name = provider.get("name")
        enabled = bool(provider.get("enabled"))
        provider_matches = by_source.get(name, []) if enabled else []
        if enabled and name in {"otx", "virustotal"} and not provider_matches:
            legacy = latest_threat_intel_for_ip(conn, indicator, name)
            if legacy:
                provider_matches = [
                    {
                        "indicator": legacy.get("indicator"),
                        "indicator_type": legacy.get("indicator_type") or indicator_type,
                        "source": name,
                        "category": legacy.get("reputation"),
                        "confidence": None,
                        "source_reference": legacy.get("lookup_result"),
                        "imported_at": legacy.get("lookup_time"),
                    }
                ]
        results.append(
            {
                **provider,
                "match_count": len(provider_matches),
                "matches": provider_matches[:20],
                "result": "matched" if provider_matches else ("no_match" if enabled else "not_active"),
            }
        )
    return results


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
          detections.case_uid,
          detections.first_seen,
          detections.src_ip,
          detections.dest_ip,
          detections.python_initial_score,
          detections.mitre_id,
          detections.mitre_name,
          COALESCE(alerts.signature, (
            SELECT finding_name FROM sensor_findings
            WHERE detection_id = detections.id ORDER BY id LIMIT 1
          )) AS signature,
          COALESCE(alerts.category, 'Zeek notice') AS category,
          ai_reports.classification AS ai_classification,
          ai_reports.confidence AS ai_confidence,
          ai_reports.ai_profile_uid AS ai_profile_uid,
          ai_reports.model_identity AS ai_model_identity
        FROM detections
        LEFT JOIN alerts ON alerts.id = detections.first_alert_id
        LEFT JOIN ai_reports ON ai_reports.id = (
          SELECT MAX(a2.id) FROM ai_reports a2 WHERE a2.detection_id = detections.id
        )
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


def ip_detail(conn, ip_address, limit=100):
    normalized_ip = normalize_ip(ip_address)
    limit = max(1, min(int(limit or 100), 250))

    summary = conn.execute(
        """
        SELECT
          (SELECT COUNT(*) FROM alerts WHERE src_ip = ? OR dest_ip = ?) AS alert_count,
          (SELECT COUNT(*) FROM detections WHERE src_ip = ? OR dest_ip = ?) AS detection_count,
          (SELECT COUNT(*) FROM alerts WHERE src_ip = ?) AS source_alert_count,
          (SELECT COUNT(*) FROM alerts WHERE dest_ip = ?) AS destination_alert_count,
          (SELECT COUNT(*) FROM detections WHERE src_ip = ?) AS source_detection_count,
          (SELECT COUNT(*) FROM detections WHERE dest_ip = ?) AS destination_detection_count,
          (SELECT MIN(timestamp) FROM alerts WHERE src_ip = ? OR dest_ip = ?) AS first_seen,
          (SELECT MAX(timestamp) FROM alerts WHERE src_ip = ? OR dest_ip = ?) AS last_seen
        """,
        (
            normalized_ip,
            normalized_ip,
            normalized_ip,
            normalized_ip,
            normalized_ip,
            normalized_ip,
            normalized_ip,
            normalized_ip,
            normalized_ip,
            normalized_ip,
            normalized_ip,
            normalized_ip,
        ),
    ).fetchone()

    detection_types = conn.execute(
        """
        SELECT COALESCE(detection_type, 'unknown') AS detection_type, COUNT(*) AS count
        FROM detections
        WHERE src_ip = ? OR dest_ip = ?
        GROUP BY COALESCE(detection_type, 'unknown')
        ORDER BY count DESC, detection_type ASC
        LIMIT ?
        """,
        (normalized_ip, normalized_ip, limit),
    ).fetchall()

    outcomes = conn.execute(
        """
        SELECT COALESCE(responses.final_classification, 'No decision') AS final_classification,
               COUNT(*) AS count
        FROM detections
        LEFT JOIN responses ON responses.id = (
          SELECT MAX(r2.id) FROM responses r2 WHERE r2.detection_id = detections.id
        )
        WHERE detections.src_ip = ? OR detections.dest_ip = ?
        GROUP BY COALESCE(responses.final_classification, 'No decision')
        ORDER BY count DESC, final_classification ASC
        """,
        (normalized_ip, normalized_ip),
    ).fetchall()

    peers = conn.execute(
        """
        SELECT peer_ip, SUM(count) AS count
        FROM (
          SELECT dest_ip AS peer_ip, COUNT(*) AS count
          FROM detections
          WHERE src_ip = ? AND dest_ip IS NOT NULL
          GROUP BY dest_ip
          UNION ALL
          SELECT src_ip AS peer_ip, COUNT(*) AS count
          FROM detections
          WHERE dest_ip = ? AND src_ip IS NOT NULL
          GROUP BY src_ip
        )
        WHERE peer_ip IS NOT NULL
        GROUP BY peer_ip
        ORDER BY count DESC
        LIMIT ?
        """,
        (normalized_ip, normalized_ip, limit),
    ).fetchall()

    detections = conn.execute(
        """
        SELECT
          detections.id AS detection_id,
          detections.case_uid,
          detections.first_seen,
          detections.last_seen,
          detections.src_ip,
          detections.dest_ip,
          detections.detection_type,
          detections.alert_count,
          detections.unique_dest_ports,
          detections.unique_dest_hosts,
          detections.time_window_seconds,
          detections.mitre_id,
          detections.mitre_name,
          detections.python_initial_score,
          alerts.timestamp,
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
          ai_reports.summary AS ai_summary,
          ai_reports.who_summary AS ai_who,
          ai_reports.what_summary AS ai_what,
          ai_reports.when_summary AS ai_when,
          ai_reports.where_summary AS ai_where,
          ai_reports.why_summary AS ai_why,
          ai_reports.how_summary AS ai_how,
          ai_reports.next_steps_json AS ai_next_steps_json,
          ai_reports.ai_profile_uid AS ai_profile_uid,
          ai_reports.model_identity AS ai_model_identity,
          responses.final_score,
          responses.final_classification,
          responses.final_action,
          responses.target_ip,
          analyst_reviews.review_status,
          analyst_reviews.analyst_action
        FROM detections
        LEFT JOIN alerts ON alerts.id = detections.first_alert_id
        LEFT JOIN ai_reports ON ai_reports.id = (
          SELECT MAX(a2.id) FROM ai_reports a2 WHERE a2.detection_id = detections.id
        )
        LEFT JOIN responses ON responses.id = (
          SELECT MAX(r2.id) FROM responses r2 WHERE r2.detection_id = detections.id
        )
        LEFT JOIN analyst_reviews ON analyst_reviews.detection_id = detections.id
        WHERE detections.src_ip = ? OR detections.dest_ip = ?
        ORDER BY detections.id DESC
        LIMIT ?
        """,
        (normalized_ip, normalized_ip, limit),
    ).fetchall()

    alerts = conn.execute(
        """
        SELECT
          alerts.id AS alert_id,
          COALESCE(alerts.timestamp, detections.first_seen) AS timestamp,
          COALESCE(alerts.src_ip, detections.src_ip) AS src_ip,
          COALESCE(alerts.dest_ip, detections.dest_ip) AS dest_ip,
          COALESCE(alerts.src_port, detections.src_port) AS src_port,
          COALESCE(alerts.dest_port, detections.dest_port) AS dest_port,
          COALESCE(alerts.protocol, detections.protocol) AS protocol,
          COALESCE(alerts.signature, (
            SELECT finding_name FROM sensor_findings
            WHERE detection_id = detections.id ORDER BY id LIMIT 1
          )) AS signature,
          COALESCE(alerts.category, 'Zeek notice') AS category,
          COALESCE(alerts.priority, 3) AS priority,
          detections.id AS detection_id,
          detections.detection_type
        FROM alerts
        LEFT JOIN detections ON detections.first_alert_id = alerts.id
        WHERE alerts.src_ip = ? OR alerts.dest_ip = ?
        ORDER BY alerts.id DESC
        LIMIT ?
        """,
        (normalized_ip, normalized_ip, limit),
    ).fetchall()

    intel_history = conn.execute(
        """
        SELECT indicator, indicator_type, source, reputation, malicious_count,
               suspicious_count, lookup_result, lookup_time, cached
        FROM threat_intel_lookups
        WHERE indicator = ?
        ORDER BY lookup_time DESC, id DESC
        LIMIT 25
        """,
        (normalized_ip,),
    ).fetchall()

    def enrich_ip_row(row):
        item = {
            **dict(row),
            **ip_enrichment_profile(row["peer_ip"]),
        }
        item["asset"] = lookup_asset(conn, row["peer_ip"])
        item["otx"] = latest_threat_intel_for_ip(conn, row["peer_ip"], "otx")
        return item

    detection_rows = []
    for row in detections:
        item = dict(row)
        item["role"] = "source" if item.get("src_ip") == normalized_ip else "destination"
        if item.get("src_ip") == normalized_ip and item.get("dest_ip") == normalized_ip:
            item["role"] = "source and destination"
        item["src_asset"] = lookup_asset(conn, item.get("src_ip"))
        item["dest_asset"] = lookup_asset(conn, item.get("dest_ip"))
        detection_rows.append(item)

    return {
        "ip_address": normalized_ip,
        "profile": ip_enrichment_profile(normalized_ip),
        "asset": lookup_asset(conn, normalized_ip),
        "otx": latest_threat_intel_for_ip(conn, normalized_ip, "otx"),
        "summary": dict(summary) if summary else {},
        "detection_types": [dict(row) for row in detection_types],
        "outcomes": [dict(row) for row in outcomes],
        "peers": [enrich_ip_row(row) for row in peers],
        "detections": detection_rows,
        "alerts": [dict(row) for row in alerts],
        "intel_history": [dict(row) for row in intel_history],
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
    filters = [
        "responses.id = (SELECT MAX(r2.id) FROM responses r2 WHERE r2.detection_id = detections.id)"
    ]
    if detection_type:
        filters.append("detections.detection_type = ?")
        params.append(detection_type)
    if outcome == "dangerous":
        filters.append("lower(COALESCE(responses.final_classification, '')) = 'dangerous'")
    elif outcome == "human_review":
        filters.append(
            """
            lower(COALESCE(responses.final_classification, '')) LIKE '%human%'
            """
        )
    elif outcome == "high_risk":
        filters.append("lower(COALESCE(responses.final_classification, '')) = 'high risk'")
    elif outcome == "safe":
        filters.append("lower(COALESCE(responses.final_classification, '')) = 'safe'")
    filter_sql = f"WHERE {' AND '.join(filters)}" if filters else ""
    params.append(limit)

    rows = conn.execute(
        f"""
        SELECT
          responses.id AS response_id,
          responses.detection_id,
          detections.case_uid,
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
          detections.sensor_state,
          detections.agreement_state,
          detections.correlation_method,
          detections.correlation_confidence,
          detections.community_id,
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
          ai_reports.summary AS ai_summary,
          ai_reports.who_summary AS ai_who,
          ai_reports.what_summary AS ai_what,
          ai_reports.when_summary AS ai_when,
          ai_reports.where_summary AS ai_where,
          ai_reports.why_summary AS ai_why,
          ai_reports.how_summary AS ai_how,
          ai_reports.next_steps_json AS ai_next_steps_json,
          ai_reports.reason AS ai_reason,
          ai_reports.recommended_action AS ai_recommended_action,
          ai_reports.ai_profile_uid AS ai_profile_uid,
          ai_reports.model_provider AS ai_model_provider,
          ai_reports.model_name AS ai_model_name,
          ai_reports.model_identity AS ai_model_identity,
          ai_reports.model_run_id AS ai_model_run_id,
          ai_reports.prompt_version AS ai_prompt_version,
          ai_reports.elapsed_ms AS ai_elapsed_ms,
          ai_reports.prompt_sha256 AS ai_prompt_sha256,
          ai_reports.prompt_chars AS ai_prompt_chars,
          analyst_reviews.review_status,
          analyst_reviews.analyst_name,
          analyst_reviews.analyst_score,
          analyst_reviews.analyst_action
        FROM responses
        LEFT JOIN detections ON detections.id = responses.detection_id
        LEFT JOIN alerts ON alerts.id = detections.first_alert_id
        LEFT JOIN ai_reports ON ai_reports.id = (
          SELECT MAX(a2.id) FROM ai_reports a2 WHERE a2.detection_id = detections.id
        )
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
        item["sensor_findings"] = sensor_findings_for_detection(conn, item["detection_id"])
        try:
            item["ai_next_steps"] = json.loads(item.get("ai_next_steps_json") or "[]")
        except (TypeError, ValueError, json.JSONDecodeError):
            item["ai_next_steps"] = []
        if not item.get("timestamp") and item["sensor_findings"]:
            item["timestamp"] = item["sensor_findings"][0].get("finding_timestamp")
        evidence.append(item)
    return evidence


def investigation_detail(conn, detection_id):
    row = conn.execute(
        """
        SELECT
          detections.id AS detection_id,
          detections.case_uid,
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
          detections.sensor_state,
          detections.agreement_state,
          detections.correlation_method,
          detections.correlation_confidence,
          detections.community_id,
          detections.status AS detection_status,
          alerts.id AS alert_id,
          alerts.event_uid AS alert_event_uid,
          COALESCE(alerts.timestamp, detections.first_seen) AS timestamp,
          COALESCE(alerts.src_ip, detections.src_ip) AS src_ip,
          COALESCE(alerts.dest_ip, detections.dest_ip) AS dest_ip,
          COALESCE(alerts.src_port, detections.src_port) AS src_port,
          COALESCE(alerts.dest_port, detections.dest_port) AS dest_port,
          COALESCE(alerts.protocol, detections.protocol) AS protocol,
          alerts.signature,
          alerts.category,
          alerts.priority,
          alerts.raw_json,
          ai_reports.classification AS ai_classification,
          ai_reports.confidence AS ai_confidence,
          ai_reports.risk_adjustment AS ai_risk_adjustment,
          ai_reports.reason AS ai_reason,
          ai_reports.recommended_action AS ai_recommended_action,
          ai_reports.summary AS ai_summary,
          ai_reports.who_summary AS ai_who,
          ai_reports.what_summary AS ai_what,
          ai_reports.when_summary AS ai_when,
          ai_reports.where_summary AS ai_where,
          ai_reports.why_summary AS ai_why,
          ai_reports.how_summary AS ai_how,
          ai_reports.next_steps_json AS ai_next_steps_json,
          ai_reports.threat_intel_analysis_json AS ai_threat_intel_analysis_json,
          ai_reports.raw_response AS ai_raw_response,
          ai_reports.ai_profile_uid AS ai_profile_uid,
          ai_reports.model_provider AS ai_model_provider,
          ai_reports.model_name AS ai_model_name,
          ai_reports.model_identity AS ai_model_identity,
          ai_reports.model_endpoint AS ai_model_endpoint,
          ai_reports.model_run_id AS ai_model_run_id,
          ai_reports.prompt_version AS ai_prompt_version,
          ai_reports.elapsed_ms AS ai_elapsed_ms,
          ai_reports.prompt_sha256 AS ai_prompt_sha256,
          ai_reports.prompt_chars AS ai_prompt_chars,
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
        LEFT JOIN ai_reports ON ai_reports.id = (
          SELECT MAX(a2.id) FROM ai_reports a2 WHERE a2.detection_id = detections.id
        )
        LEFT JOIN responses ON responses.id = (
          SELECT MAX(r2.id) FROM responses r2 WHERE r2.detection_id = detections.id
        )
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
    if (
        item.get("ai_raw_response")
        and item.get("ai_summary") == "The model response could not be parsed."
    ):
        try:
            from app.ai_client import normalize_report, parse_model_response

            recovered = normalize_report(parse_model_response(item["ai_raw_response"]))
            for source_key, item_key in {
                "reason": "ai_reason",
                "summary": "ai_summary",
                "who": "ai_who",
                "what": "ai_what",
                "when": "ai_when",
                "where": "ai_where",
                "why": "ai_why",
                "how": "ai_how",
            }.items():
                item[item_key] = recovered.get(source_key)
            item["ai_next_steps"] = recovered.get("next_steps") or []
            item["ai_threat_intel_analysis"] = recovered.get("threat_intel_analysis") or {}
        except (TypeError, ValueError):
            pass
    try:
        if "ai_next_steps" not in item:
            item["ai_next_steps"] = json.loads(item.get("ai_next_steps_json") or "[]")
    except (TypeError, json.JSONDecodeError):
        item["ai_next_steps"] = []
    raw_threat_intel_analysis = item.pop("ai_threat_intel_analysis_json")
    if raw_threat_intel_analysis:
        try:
            item["ai_threat_intel_analysis"] = json.loads(raw_threat_intel_analysis)
        except (TypeError, json.JSONDecodeError):
            item["ai_threat_intel_analysis"] = {}
    else:
        item.setdefault("ai_threat_intel_analysis", {})
    item["src_asset"] = lookup_asset(conn, item.get("src_ip"))
    item["dest_asset"] = lookup_asset(conn, item.get("dest_ip"))
    item["src_ip_profile"] = ip_enrichment_profile(item.get("src_ip"))
    item["dest_ip_profile"] = ip_enrichment_profile(item.get("dest_ip"))
    item["src_otx"] = latest_threat_intel_for_ip(conn, item.get("src_ip"), "otx")
    item["dest_otx"] = latest_threat_intel_for_ip(conn, item.get("dest_ip"), "otx")
    item["sensor_findings"] = sensor_findings_for_detection(conn, detection_id)
    item["score_breakdowns"] = score_breakdowns_for_detection(conn, detection_id)
    item["virustotal_verifications"] = virustotal_verifications_for_detection(conn, detection_id)
    item["ai_assessments"] = [
        dict(value)
        for value in conn.execute(
            "SELECT * FROM ai_assessments WHERE detection_id = ? ORDER BY id",
            (detection_id,),
        ).fetchall()
    ]
    item["responses"] = [
        dict(value)
        for value in conn.execute(
            "SELECT * FROM responses WHERE detection_id = ? ORDER BY id",
            (detection_id,),
        ).fetchall()
    ]
    item["threat_intel_usage"] = [
        dict(value)
        for value in conn.execute(
            """
            SELECT indicator, indicator_type, source, stage, matched, details_json, used_at
            FROM threat_intel_usage WHERE detection_id = ? ORDER BY id
            """,
            (detection_id,),
        ).fetchall()
    ]
    if not item.get("signature") and item["sensor_findings"]:
        primary = item["sensor_findings"][0]
        item["signature"] = primary.get("finding_name")
        item["category"] = f"{primary.get('sensor', 'sensor')} {primary.get('finding_type', 'finding')}"
        item["timestamp"] = item.get("first_seen")
        item["src_ip"] = item.get("src_ip") or item.get("target_ip")
    return item


def case_workspace(conn, case_uid):
    detection = detection_by_case_uid(conn, case_uid)
    if not detection:
        return None
    detail = investigation_detail(conn, detection["id"])
    if not detail:
        return None
    detail["suricata_alerts"] = [
        dict(row)
        for row in conn.execute(
            """
            SELECT alerts.*
            FROM sensor_findings
            JOIN alerts ON sensor_findings.sensor = 'suricata'
                       AND alerts.id = sensor_findings.sensor_event_id
            WHERE sensor_findings.detection_id = ?
            ORDER BY alerts.timestamp, alerts.id
            """,
            (detection["id"],),
        ).fetchall()
    ]
    detail["zeek_findings"] = [
        dict(row)
        for row in conn.execute(
            """
            SELECT zeek_events.*
            FROM sensor_findings
            JOIN zeek_events ON sensor_findings.sensor = 'zeek'
                            AND zeek_events.id = sensor_findings.sensor_event_id
            WHERE sensor_findings.detection_id = ?
            ORDER BY zeek_events.timestamp, zeek_events.id
            """,
            (detection["id"],),
        ).fetchall()
    ]
    detail["zeek_context"] = zeek_context_for_detection(conn, detection["id"], seconds=120)
    return detail


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
          COALESCE(alerts.signature, (
            SELECT finding_name FROM sensor_findings
            WHERE detection_id = detections.id ORDER BY id LIMIT 1
          )) AS signature,
          COALESCE(alerts.timestamp, detections.first_seen) AS timestamp,
          ai_reports.classification AS ai_classification,
          ai_reports.confidence AS ai_confidence,
          ai_reports.reason AS ai_reason,
          ai_reports.ai_profile_uid AS ai_profile_uid,
          ai_reports.model_identity AS ai_model_identity
        FROM analyst_reviews
        LEFT JOIN detections ON detections.id = analyst_reviews.detection_id
        LEFT JOIN alerts ON alerts.id = detections.first_alert_id
        LEFT JOIN ai_reports ON ai_reports.id = (
          SELECT MAX(a2.id) FROM ai_reports a2 WHERE a2.detection_id = detections.id
        )
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
          COALESCE(alerts.timestamp, detections.first_seen) AS timestamp,
          COALESCE(alerts.src_ip, detections.src_ip) AS src_ip,
          COALESCE(alerts.dest_ip, detections.dest_ip) AS dest_ip,
          COALESCE(alerts.src_port, detections.src_port) AS src_port,
          COALESCE(alerts.dest_port, detections.dest_port) AS dest_port,
          COALESCE(alerts.protocol, detections.protocol) AS protocol,
          COALESCE(alerts.signature, (
            SELECT finding_name FROM sensor_findings
            WHERE detection_id = detections.id ORDER BY id LIMIT 1
          )) AS signature,
          COALESCE(alerts.category, 'Zeek notice') AS category,
          COALESCE(alerts.severity, 3) AS severity,
          COALESCE(alerts.priority, 3) AS priority,
          COALESCE(alerts.flow_id, '') AS flow_id,
          COALESCE(alerts.community_id, detections.community_id) AS community_id,
          alerts.pcap_point,
          alerts.raw_json,
          detections.id AS detection_id,
          detections.case_uid,
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
          detections.src_port AS detection_src_port,
          detections.dest_port AS detection_dest_port,
          detections.protocol AS detection_protocol,
          detections.community_id AS detection_community_id,
          detections.sensor_state,
          detections.agreement_state,
          detections.correlation_method,
          detections.correlation_confidence,
          detections.status
        FROM detections
        LEFT JOIN alerts ON alerts.id = detections.first_alert_id
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

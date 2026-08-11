"""SQLite persistence, migrations, correlation queries, and dashboard reads.

SQLite is the authoritative local evidence store. The schema separates four
concerns so that each stage can be explained and independently verified:

* ``alerts`` and ``zeek_events`` retain normalized sensor fields plus original
  JSON. Normal columns make correlation/querying practical; raw JSON preserves
  evidence that was not selected by today's normalizers.
* ``detections`` is the unified case record. ``sensor_findings`` is a many-to-
  one link from original sensor rows to that case, avoiding copied or flattened
  evidence when Suricata and Zeek corroborate one another.
* ``ai_reports`` provides the current readable explanation, while
  ``ai_assessments`` and ``ai_run_audits`` preserve history and exact request/
  response proof. A changed model opinion does not overwrite its source data.
* threat-intelligence, analyst-review, response, checkpoint, and runtime tables
  record enrichment, human decisions, processing progress, and service health.

Stable SUR-, ZEK-, and CASE- identifiers are presentation/audit identities;
integer primary keys remain efficient relational links. Migrations are
forward-only and preserve existing research data.
"""

import sqlite3
import json
import ipaddress
import hashlib
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.zeek_normalizer import zeek_evidence_details


SCHEMA_PATH = Path(__file__).resolve().parents[1] / "sql" / "schema.sql"


# ---------------------------------------------------------------------------
# Connection and forward-only schema migration
# ---------------------------------------------------------------------------

def connect(db_path):
    """Open a row-addressable connection shared safely by independent workers.

    Ingestion, AI processing, threat-intelligence refresh, and dashboard reads
    can overlap. WAL allows readers during writes, and the busy timeout waits
    for short write transactions rather than failing immediately.
    """
    # WAL permits dashboard readers while ingestion writes. busy_timeout makes a
    # caller wait briefly instead of immediately raising "database is locked".
    conn = sqlite3.connect(db_path, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


def init_db(db_path):
    """Open the configured database and make its schema current without reset.

    ``CREATE IF NOT EXISTS`` supplies the base layout. Idempotent migrations
    then add fields introduced by newer versions, preserving rows collected by
    earlier demonstrations instead of requiring a new database.
    """
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
        "alerts": {"event_uid": "TEXT", "event_fingerprint": "TEXT"},
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
    """Apply idempotent additions without deleting historical SQLite evidence."""
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
        # Preserve registered-IP records while replacing the retired response-era role name.
        conn.execute(
            "UPDATE assets SET device_type = 'network_router' WHERE device_type = 'firewall_router'"
        )

    ensure_ai_report_columns(conn, "ai_reports")
    ensure_ai_run_audit_table(conn)
    ensure_suricata_ingest_tables(conn)
    ensure_zeek_tables(conn)
    ensure_ai_assessments_table(conn)
    ensure_threat_intel_tables(conn)
    ensure_sensor_fusion_tables(conn)
    ensure_case_identity_columns(conn)
    ensure_virustotal_verification_table(conn)
    ensure_ai_comparison_tables(conn)
    ensure_ai_experiment_tables(conn)
    activity_columns = {
        row["name"] for row in conn.execute("PRAGMA table_info(ai_request_activity)").fetchall()
    }
    if "cancel_requested" not in activity_columns:
        conn.execute(
            "ALTER TABLE ai_request_activity ADD COLUMN cancel_requested INTEGER NOT NULL DEFAULT 0"
        )
    conn.execute(
        "INSERT OR IGNORE INTO ai_worker_control (id, paused, updated_at) VALUES (1, 0, ?)",
        (utc_now(),),
    )
    # A dashboard restart can interrupt an older synchronous comparison. Do
    # not leave those historical runs displayed as "Running" indefinitely.
    conn.execute(
        """
        UPDATE ai_comparison_runs
        SET status = 'failed',
            error_message = COALESCE(
              error_message,
              'Comparison interrupted before all model requests completed'
            ),
            completed_at = ?
        WHERE status = 'running'
          AND created_at < datetime('now', '-10 minutes')
        """,
        (utc_now(),),
    )
    conn.execute(
        """
        UPDATE ai_request_activity
        SET phase = 'failed',
            status = 'failed',
            message = 'AI request interrupted',
            cancel_requested = 1,
            error_message = COALESCE(
              error_message,
              'The application stopped before this request completed'
            ),
            updated_at = ?
        WHERE status = 'active'
          AND (
            NOT EXISTS (
              SELECT 1 FROM detections
              WHERE detections.id = ai_request_activity.detection_id
            )
            OR (
              julianday('now') - julianday(started_at)
            ) * 86400 > COALESCE(timeout_seconds, 90) + 60
          )
        """,
        (utc_now(),),
    )
    ensure_evaluation_tables(conn)
    migrate_legacy_ai_reports(conn)
    migrate_analyst_review_classification(conn)

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


def migrate_analyst_review_classification(conn):
    """Rename legacy review labels while preserving raw model/audit evidence."""
    classification_columns = {
        "ai_reports": ("classification",),
        "ai_assessments": ("classification",),
        "ai_comparison_candidates": ("classification",),
        "responses": ("final_classification",),
        "analyst_reviews": ("original_classification", "analyst_classification"),
        "evaluation_scenarios": (
            "expected_min_classification",
            "expected_max_classification",
        ),
    }
    legacy_values = ("human review required", "human review", "review")
    for table_name, column_names in classification_columns.items():
        if not table_exists(conn, table_name):
            continue
        columns = table_columns(conn, table_name)
        for column_name in column_names:
            if column_name not in columns:
                continue
            placeholders = ", ".join("?" for _ in legacy_values)
            conn.execute(
                f"""
                UPDATE {table_name}
                SET {column_name} = 'Analyst Review Required'
                WHERE lower(trim(COALESCE({column_name}, ''))) IN ({placeholders})
                """,
                legacy_values,
            )


def ensure_ai_comparison_tables(conn):
    """Create or update the tables used for model comparisons."""
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
        CREATE TABLE IF NOT EXISTS ai_comparison_review_history (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          comparison_run_id INTEGER NOT NULL,
          analyst_name TEXT NOT NULL,
          selection TEXT NOT NULL,
          notes TEXT,
          reviewed_at TEXT,
          reopened_at TEXT NOT NULL,
          FOREIGN KEY (comparison_run_id) REFERENCES ai_comparison_runs(id)
        );
        CREATE INDEX IF NOT EXISTS idx_ai_comparison_review_history_run
          ON ai_comparison_review_history(comparison_run_id, id DESC);
        CREATE TABLE IF NOT EXISTS ai_case_explanation_promotions (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          detection_id INTEGER NOT NULL,
          case_uid TEXT NOT NULL,
          comparison_run_id INTEGER NOT NULL,
          candidate_id INTEGER NOT NULL,
          analyst_name TEXT NOT NULL,
          notes TEXT,
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (detection_id) REFERENCES detections(id),
          FOREIGN KEY (comparison_run_id) REFERENCES ai_comparison_runs(id),
          FOREIGN KEY (candidate_id) REFERENCES ai_comparison_candidates(id)
        );
        CREATE INDEX IF NOT EXISTS idx_ai_case_explanation_promotions_detection
          ON ai_case_explanation_promotions(detection_id, id DESC);
        CREATE INDEX IF NOT EXISTS idx_ai_case_explanation_promotions_run
          ON ai_case_explanation_promotions(comparison_run_id, id DESC);
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
    run_additions = {
        "expected_candidate_count": "INTEGER NOT NULL DEFAULT 3",
        "selected_profile_uids_json": "TEXT NOT NULL DEFAULT '[]'",
        "execution_order_json": "TEXT NOT NULL DEFAULT '[]'",
        "control_temperature": "REAL NOT NULL DEFAULT 0.0",
        "control_seed": "INTEGER NOT NULL DEFAULT 42",
        "control_snapshot_locked_at": "TEXT",
        "prompt_text": "TEXT",
        "prompt_sha256": "TEXT",
        "evidence_package_json": "TEXT",
        "evidence_manifest_json": "TEXT",
        "omission_manifest_json": "TEXT",
        "source_map_json": "TEXT",
        "control_request_options_json": "TEXT",
        "model_inventory_json": "TEXT NOT NULL DEFAULT '{}'",
        "worker_claimed_at": "TEXT",
    }
    for name, definition in run_additions.items():
        if name not in run_columns:
            conn.execute(f"ALTER TABLE ai_comparison_runs ADD COLUMN {name} {definition}")
    candidate_additions = {
        "evidence_sha256": "TEXT",
        "response_sha256": "TEXT",
        "model_digest": "TEXT",
        "model_size": "INTEGER",
        "model_quantization": "TEXT",
        "request_options_json": "TEXT NOT NULL DEFAULT '{}'",
        "response_metrics_json": "TEXT NOT NULL DEFAULT '{}'",
        "parse_status": "TEXT",
    }
    for name, definition in candidate_additions.items():
        if name not in candidate_columns:
            conn.execute(
                f"ALTER TABLE ai_comparison_candidates ADD COLUMN {name} {definition}"
            )


def ensure_ai_experiment_tables(conn):
    """Create durable evaluation jobs without modifying baseline comparisons."""
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS ai_experiment_runs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          experiment_uid TEXT NOT NULL UNIQUE,
          experiment_type TEXT NOT NULL,
          parent_comparison_uid TEXT NOT NULL,
          parent_winner_candidate_id INTEGER,
          case_uid TEXT NOT NULL,
          detection_id INTEGER NOT NULL,
          status TEXT NOT NULL DEFAULT 'queued',
          total_task_count INTEGER NOT NULL DEFAULT 0,
          completed_task_count INTEGER NOT NULL DEFAULT 0,
          failed_task_count INTEGER NOT NULL DEFAULT 0,
          configuration_json TEXT NOT NULL DEFAULT '{}',
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          started_at TEXT,
          completed_at TEXT,
          worker_claimed_at TEXT,
          error_summary TEXT,
          FOREIGN KEY (detection_id) REFERENCES detections(id),
          FOREIGN KEY (parent_winner_candidate_id) REFERENCES ai_comparison_candidates(id)
        );
        CREATE INDEX IF NOT EXISTS idx_ai_experiment_runs_parent
          ON ai_experiment_runs(parent_comparison_uid, id DESC);
        CREATE INDEX IF NOT EXISTS idx_ai_experiment_runs_status
          ON ai_experiment_runs(status, id);

        CREATE TABLE IF NOT EXISTS ai_experiment_results (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          result_uid TEXT NOT NULL UNIQUE,
          experiment_run_id INTEGER NOT NULL,
          baseline_candidate_id INTEGER NOT NULL,
          ai_profile_uid TEXT NOT NULL,
          anonymous_label TEXT NOT NULL,
          model_provider TEXT,
          model_name TEXT,
          model_identity TEXT,
          model_digest TEXT,
          model_size INTEGER,
          model_quantization TEXT,
          variant_label TEXT NOT NULL,
          temperature REAL NOT NULL,
          seed INTEGER NOT NULL,
          evidence_mask_json TEXT NOT NULL DEFAULT '[]',
          parent_prompt_sha256 TEXT,
          parent_evidence_sha256 TEXT,
          parent_response_sha256 TEXT,
          prompt_text TEXT,
          prompt_sha256 TEXT,
          evidence_package_json TEXT,
          evidence_sha256 TEXT,
          response_sha256 TEXT,
          classification TEXT,
          confidence TEXT,
          summary TEXT,
          who_summary TEXT,
          what_summary TEXT,
          when_summary TEXT,
          where_summary TEXT,
          why_summary TEXT,
          how_summary TEXT,
          next_steps_json TEXT NOT NULL DEFAULT '[]',
          recommended_action TEXT,
          raw_response TEXT,
          request_options_json TEXT NOT NULL DEFAULT '{}',
          response_metrics_json TEXT NOT NULL DEFAULT '{}',
          elapsed_ms INTEGER,
          parse_status TEXT,
          status TEXT NOT NULL DEFAULT 'queued',
          error_message TEXT,
          grounding_score INTEGER,
          completeness_score INTEGER,
          next_step_quality_score INTEGER,
          uncertainty_score INTEGER,
          usefulness_score INTEGER,
          supported_claims INTEGER,
          unsupported_claims INTEGER,
          contradicted_claims INTEGER,
          undecidable_claims INTEGER,
          missing_evidence_acknowledged INTEGER,
          reviewer_name TEXT,
          reviewer_notes TEXT,
          reviewed_at TEXT,
          started_at TEXT,
          completed_at TEXT,
          worker_claimed_at TEXT,
          FOREIGN KEY (experiment_run_id) REFERENCES ai_experiment_runs(id),
          FOREIGN KEY (baseline_candidate_id) REFERENCES ai_comparison_candidates(id)
        );
        CREATE INDEX IF NOT EXISTS idx_ai_experiment_results_run
          ON ai_experiment_results(experiment_run_id, id);
        CREATE INDEX IF NOT EXISTS idx_ai_experiment_results_status
          ON ai_experiment_results(status, id);
        """
    )


def ensure_evaluation_tables(conn):
    """Create or update the tables used by the Evaluation Lab."""
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS evaluation_scenarios (
          scenario_uid TEXT PRIMARY KEY,
          name TEXT NOT NULL,
          experiment_type TEXT NOT NULL,
          ground_truth_class TEXT NOT NULL,
          authorized_activity INTEGER,
          attack_succeeded INTEGER,
          source_ip TEXT,
          destination_ip TEXT,
          start_time TEXT NOT NULL,
          end_time TEXT NOT NULL,
          expected_case_count INTEGER NOT NULL DEFAULT 1,
          expected_min_classification TEXT,
          expected_max_classification TEXT,
          expected_sensors TEXT NOT NULL DEFAULT '[]',
          candidate_scope_json TEXT NOT NULL DEFAULT '{}',
          notes TEXT,
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_evaluation_scenarios_experiment
          ON evaluation_scenarios(experiment_type, start_time DESC);

        CREATE TABLE IF NOT EXISTS evaluation_case_links (
          scenario_uid TEXT NOT NULL,
          case_uid TEXT NOT NULL,
          relationship_status TEXT NOT NULL DEFAULT 'expected_related',
          analyst_confirmed INTEGER NOT NULL DEFAULT 0,
          notes TEXT,
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          PRIMARY KEY (scenario_uid, case_uid),
          FOREIGN KEY (scenario_uid) REFERENCES evaluation_scenarios(scenario_uid)
        );
        CREATE INDEX IF NOT EXISTS idx_evaluation_case_links_case
          ON evaluation_case_links(case_uid);

        CREATE TABLE IF NOT EXISTS evaluation_event_labels (
          scenario_uid TEXT NOT NULL,
          event_uid TEXT NOT NULL,
          event_sensor TEXT NOT NULL,
          expected_case_uid TEXT,
          actual_case_uid TEXT,
          expected_membership INTEGER NOT NULL,
          actual_membership INTEGER NOT NULL,
          label TEXT NOT NULL,
          notes TEXT,
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          PRIMARY KEY (scenario_uid, event_sensor, event_uid),
          FOREIGN KEY (scenario_uid) REFERENCES evaluation_scenarios(scenario_uid)
        );

        CREATE TABLE IF NOT EXISTS evaluation_model_reviews (
          review_uid TEXT PRIMARY KEY,
          comparison_run_uid TEXT NOT NULL,
          profile_uid TEXT NOT NULL,
          anonymous_label TEXT NOT NULL,
          grounding_score INTEGER NOT NULL,
          completeness_score INTEGER NOT NULL,
          next_steps_score INTEGER NOT NULL,
          uncertainty_score INTEGER NOT NULL,
          usefulness_score INTEGER NOT NULL,
          supported_claims INTEGER NOT NULL DEFAULT 0,
          unsupported_claims INTEGER NOT NULL DEFAULT 0,
          contradicted_claims INTEGER NOT NULL DEFAULT 0,
          undecidable_claims INTEGER NOT NULL DEFAULT 0,
          notes TEXT,
          reviewer_name TEXT NOT NULL,
          reviewed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(comparison_run_uid, profile_uid)
        );
        CREATE INDEX IF NOT EXISTS idx_evaluation_model_reviews_run
          ON evaluation_model_reviews(comparison_run_uid, reviewed_at DESC);
        """
    )
    scenario_columns = {
        row["name"]
        for row in conn.execute("PRAGMA table_info(evaluation_scenarios)").fetchall()
    }
    if "candidate_scope_json" not in scenario_columns:
        conn.execute(
            "ALTER TABLE evaluation_scenarios "
            "ADD COLUMN candidate_scope_json TEXT NOT NULL DEFAULT '{}'"
        )
    event_columns = {
        row["name"]
        for row in conn.execute("PRAGMA table_info(evaluation_event_labels)").fetchall()
    }
    if "expected_case_uid" not in event_columns:
        conn.execute(
            "ALTER TABLE evaluation_event_labels ADD COLUMN expected_case_uid TEXT"
        )
    conn.execute(
        """
        UPDATE evaluation_event_labels
        SET expected_case_uid = actual_case_uid
        WHERE expected_case_uid IS NULL
          AND expected_membership = 1
          AND actual_membership = 1
          AND actual_case_uid IS NOT NULL
        """
    )
    conn.execute(
        """
        UPDATE evaluation_event_labels
        SET expected_case_uid = (
          SELECT MIN(links.case_uid)
          FROM evaluation_case_links AS links
          WHERE links.scenario_uid = evaluation_event_labels.scenario_uid
        )
        WHERE expected_case_uid IS NULL
          AND expected_membership = 1
          AND actual_membership = 0
          AND (
            SELECT COUNT(*)
            FROM evaluation_case_links AS links
            WHERE links.scenario_uid = evaluation_event_labels.scenario_uid
          ) = 1
        """
    )


def table_exists(conn, table_name):
    """Return whether a named SQLite table exists in the current database."""
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table_name,),
    ).fetchone()
    return row is not None


def table_columns(conn, table_name):
    """Return the column names for an existing SQLite table."""
    if not table_exists(conn, table_name):
        return set()
    return {
        row["name"] for row in conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    }


def ensure_suricata_ingest_tables(conn):
    """Create Suricata restart checkpoints and content-based deduplication.

    The inode/offset identifies where the file reader stopped. The fingerprint
    protects against replay when a rotated or copied EVE file presents the same
    alert at another offset.
    """
    alert_columns = {
        row["name"] for row in conn.execute("PRAGMA table_info(alerts)").fetchall()
    }
    if "event_fingerprint" not in alert_columns:
        conn.execute("ALTER TABLE alerts ADD COLUMN event_fingerprint TEXT")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS suricata_ingest_checkpoints (
          source TEXT PRIMARY KEY,
          path TEXT NOT NULL,
          inode INTEGER NOT NULL,
          offset INTEGER NOT NULL DEFAULT 0,
          updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_event_fingerprint "
        "ON alerts(event_fingerprint) WHERE event_fingerprint IS NOT NULL"
    )


def _uid_date(value):
    """Convert an event timestamp into the date segment used by stable UIDs."""
    try:
        parsed = datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
    except ValueError:
        parsed = datetime.now(timezone.utc)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).strftime("%Y%m%d")


def stable_record_uid(prefix, record_id, timestamp):
    """Create readable, stable record IDs such as SUR-, ZEK-, and CASE- IDs."""
    return f"{prefix}-{_uid_date(timestamp)}-{int(record_id):06d}"


def ensure_case_identity_columns(conn):
    """Backfill stable UIDs for databases created before case identities existed."""
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


def ensure_virustotal_verification_table(conn):
    """Create or update the table that stores VirusTotal checks."""
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
        "CREATE INDEX IF NOT EXISTS idx_vt_verifications_detection "
        "ON virustotal_verifications(detection_id, assessment_stage)"
    )


def ensure_ai_report_columns(conn, table_name):
    """Add AI report columns missing from an older database."""
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
        "summary": f"ALTER TABLE {table_name} ADD COLUMN summary TEXT",
        "who_summary": f"ALTER TABLE {table_name} ADD COLUMN who_summary TEXT",
        "what_summary": f"ALTER TABLE {table_name} ADD COLUMN what_summary TEXT",
        "when_summary": f"ALTER TABLE {table_name} ADD COLUMN when_summary TEXT",
        "where_summary": f"ALTER TABLE {table_name} ADD COLUMN where_summary TEXT",
        "why_summary": f"ALTER TABLE {table_name} ADD COLUMN why_summary TEXT",
        "how_summary": f"ALTER TABLE {table_name} ADD COLUMN how_summary TEXT",
        "next_steps_json": f"ALTER TABLE {table_name} ADD COLUMN next_steps_json TEXT",
        "threat_intel_analysis_json": f"ALTER TABLE {table_name} ADD COLUMN threat_intel_analysis_json TEXT",
        "evidence_review_json": f"ALTER TABLE {table_name} ADD COLUMN evidence_review_json TEXT",
    }
    for column, statement in report_migrations.items():
        if column not in report_columns:
            conn.execute(statement)


def ensure_ai_run_audit_table(conn):
    """Create the proof table containing exact AI requests and responses.

    This table is intentionally separate from the readable ``ai_reports`` row:
    it records prompt/evidence text, hashes, source lineage, omissions, request
    options, token metrics, parse status, and raw output for reproducibility.
    """
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS ai_run_audits (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          detection_id INTEGER NOT NULL,
          ai_report_id INTEGER,
          assessment_type TEXT NOT NULL DEFAULT 'initial',
          model_run_id TEXT NOT NULL,
          ai_profile_uid TEXT,
          model_provider TEXT,
          model_name TEXT,
          model_endpoint TEXT,
          prompt_version TEXT,
          prompt_text TEXT NOT NULL,
          prompt_sha256 TEXT NOT NULL,
          prompt_chars INTEGER NOT NULL,
          prompt_bytes INTEGER NOT NULL,
          evidence_package_json TEXT NOT NULL,
          evidence_sha256 TEXT NOT NULL,
          evidence_chars INTEGER NOT NULL,
          evidence_bytes INTEGER NOT NULL,
          evidence_manifest_json TEXT NOT NULL,
          omission_manifest_json TEXT NOT NULL,
          source_map_json TEXT NOT NULL,
          request_options_json TEXT NOT NULL,
          response_metrics_json TEXT NOT NULL DEFAULT '{}',
          response_text TEXT,
          response_sha256 TEXT,
          response_chars INTEGER,
          response_bytes INTEGER,
          parse_status TEXT,
          parse_error TEXT,
          status TEXT NOT NULL DEFAULT 'prepared',
          prepared_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          responded_at TEXT,
          UNIQUE(detection_id, model_run_id),
          FOREIGN KEY (detection_id) REFERENCES detections(id),
          FOREIGN KEY (ai_report_id) REFERENCES ai_reports(id)
        );
        CREATE INDEX IF NOT EXISTS idx_ai_run_audits_detection
          ON ai_run_audits(detection_id, id DESC);
        """
    )
    audit_columns = {
        row["name"] for row in conn.execute("PRAGMA table_info(ai_run_audits)").fetchall()
    }
    if "response_metrics_json" not in audit_columns:
        conn.execute(
            "ALTER TABLE ai_run_audits ADD COLUMN response_metrics_json TEXT NOT NULL DEFAULT '{}'"
        )


def ensure_zeek_tables(conn):
    """Create Zeek source rows and one checkpoint per protocol log.

    Zeek rotates conn, DNS, TLS, notice, and other logs independently. A single
    global offset would therefore skip or repeat evidence, so each ``log_type``
    owns its path/inode/offset state.
    """
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
    """Create the many-to-one links that join sensor rows into cases.

    ``detections`` stores case-level time, endpoint, and correlation state.
    ``sensor_findings`` identifies the exact Suricata or Zeek row supporting
    that case. This preserves sensor disagreement and allows multiple findings
    without duplicating their complete raw JSON in the case table.
    """
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
    """Create or update the table that keeps assessment history."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS ai_assessments (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          detection_id INTEGER NOT NULL,
          assessment_type TEXT NOT NULL,
          provider TEXT,
          model_name TEXT NOT NULL,
          classification TEXT NOT NULL,
          confidence REAL,
          reason TEXT,
          recommended_action TEXT,
          evidence_sources_json TEXT,
          response_time_ms INTEGER,
          raw_response TEXT,
          created_at TEXT NOT NULL,
          FOREIGN KEY (detection_id) REFERENCES detections(id)
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ai_assessments_detection ON ai_assessments(detection_id, assessment_type)")


def ensure_threat_intel_tables(conn):
    """Create or update the threat-intelligence cache tables."""
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
    """Copy reports from the retired model-specific table into ai_reports."""
    legacy_table = "olla" + "ma_reports"
    if not table_exists(conn, legacy_table):
        return
    ensure_ai_report_columns(conn, legacy_table)
    conn.execute(
        f"""
        INSERT OR IGNORE INTO ai_reports (
          id, detection_id, ai_profile_uid, model_provider, model_name,
          model_identity, model_endpoint, model_run_id, prompt_version,
          classification, confidence, reason,
          recommended_action, raw_response, elapsed_ms, prompt_sha256,
          prompt_chars, created_at
        )
        SELECT
          id, detection_id, ai_profile_uid, model_provider, model_name,
          model_identity, model_endpoint, model_run_id, prompt_version,
          classification, confidence, reason,
          recommended_action, raw_response, elapsed_ms, prompt_sha256,
          prompt_chars, created_at
        FROM {legacy_table}
        """
    )


def utc_now():
    """Return the current UTC timestamp in the database storage format."""
    return datetime.now(timezone.utc).isoformat()


LEGACY_OPERATIONAL_SCORE_FIELDS = {
    "python_initial_score",
    "final_score",
    "risk_adjustment",
    "ai_risk_adjustment",
    "analyst_score",
    "original_score",
}


def without_operational_scores(value):
    """Remove retired score keys from API read models while preserving old rows."""
    item = dict(value)
    for key in LEGACY_OPERATIONAL_SCORE_FIELDS:
        item.pop(key, None)
    return item


def new_ai_profile_uid():
    """Create a unique ID for an AI profile."""
    return f"ai-{uuid.uuid4().hex[:12]}"


def new_ai_comparison_uid():
    """Create a unique ID for an AI comparison."""
    return f"cmp-{uuid.uuid4().hex[:16]}"


def new_ai_activity_uid():
    """Create a unique ID for an AI request activity."""
    return f"air-{uuid.uuid4().hex[:16]}"


def create_ai_request_activity(
    conn,
    assessment_type,
    case_uid=None,
    detection_id=None,
    comparison_uid=None,
    anonymous_slot=None,
):
    """Start one sanitized lifecycle record for an outbound AI request."""
    activity_uid = new_ai_activity_uid()
    now = utc_now()
    conn.execute(
        """
        INSERT INTO ai_request_activity (
          activity_uid, case_uid, detection_id, comparison_uid, anonymous_slot,
          assessment_type, phase, status, message, started_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, 'preparing', 'active',
                'Preparing normalized evidence', ?, ?)
        """,
        (
            activity_uid,
            case_uid,
            detection_id,
            comparison_uid,
            anonymous_slot,
            assessment_type,
            now,
            now,
        ),
    )
    conn.commit()
    return activity_uid


def update_ai_request_activity(conn, activity_uid, phase, details=None):
    """Advance an AI request lifecycle using an allow-listed metadata set."""
    details = details or {}
    status = details.get("status")
    if status not in {"active", "complete", "failed", "cancelled"}:
        status = "failed" if phase == "failed" else "complete" if phase == "complete" else "active"
    messages = {
        "preparing": "Preparing normalized evidence",
        "prompt_ready": "Prompt built and request settings prepared",
        "requesting": "API request sent; waiting for model response",
        "response_received": "Model response received",
        "parsing": "Validating structured model response",
        "complete": "AI request completed",
        "failed": "AI request failed",
        "cancelled": "AI request cancelled by user",
    }
    conn.execute(
        """
        UPDATE ai_request_activity
        SET phase = ?,
            status = ?,
            message = ?,
            prompt_chars = COALESCE(?, prompt_chars),
            prompt_bytes = COALESCE(?, prompt_bytes),
            estimated_tokens = COALESCE(?, estimated_tokens),
            timeout_seconds = COALESCE(?, timeout_seconds),
            elapsed_ms = COALESCE(?, elapsed_ms),
            parse_status = COALESCE(?, parse_status),
            error_message = COALESCE(?, error_message),
            updated_at = ?
        WHERE activity_uid = ?
        """,
        (
            phase,
            status,
            messages.get(phase, str(details.get("message") or phase)),
            details.get("prompt_chars"),
            details.get("prompt_bytes"),
            details.get("estimated_tokens"),
            details.get("timeout_seconds"),
            details.get("elapsed_ms"),
            details.get("parse_status"),
            details.get("error_message"),
            utc_now(),
            activity_uid,
        ),
    )
    conn.commit()


def ai_request_cancel_requested(conn, activity_uid):
    """Return whether an operator requested cancellation of this AI activity."""
    row = conn.execute(
        "SELECT cancel_requested FROM ai_request_activity WHERE activity_uid = ?",
        (activity_uid,),
    ).fetchone()
    return bool(row and row["cancel_requested"])


def cancel_ai_request(conn, activity_uid):
    """Cancel one active request and suppress automatic retry of its case."""
    row = conn.execute(
        "SELECT detection_id FROM ai_request_activity WHERE activity_uid = ? AND status = 'active'",
        (activity_uid,),
    ).fetchone()
    if not row:
        return False
    now = utc_now()
    conn.execute(
        """
        UPDATE ai_request_activity
        SET cancel_requested = 1, phase = 'cancelled', status = 'cancelled',
            message = 'AI request cancelled by user', updated_at = ?
        WHERE activity_uid = ?
        """,
        (now, activity_uid),
    )
    if row["detection_id"] is not None:
        conn.execute(
            """
            INSERT INTO ai_cancelled_detections (detection_id, activity_uid, cancelled_at)
            VALUES (?, ?, ?)
            ON CONFLICT(detection_id) DO UPDATE SET
              activity_uid = excluded.activity_uid,
              cancelled_at = excluded.cancelled_at
            """,
            (row["detection_id"], activity_uid, now),
        )
    conn.commit()
    return True


def cancel_all_ai_requests(conn):
    """Pause initial AI processing and cancel every currently active request."""
    active = conn.execute(
        "SELECT activity_uid FROM ai_request_activity WHERE status = 'active'"
    ).fetchall()
    for row in active:
        cancel_ai_request(conn, row["activity_uid"])
    conn.execute(
        "UPDATE ai_worker_control SET paused = 1, updated_at = ? WHERE id = 1",
        (utc_now(),),
    )
    conn.commit()
    return len(active)


def interrupt_active_ai_requests(conn, reason="Application restarted before request completed"):
    """Close lifecycle rows whose HTTP connections cannot survive a restart.

    This deliberately does not suppress their detections. The newly started AI
    worker can retry each unassessed case once with a fresh activity record.
    """
    now = utc_now()
    cursor = conn.execute(
        """
        UPDATE ai_request_activity
        SET phase = 'failed',
            status = 'failed',
            message = 'AI request interrupted by application restart',
            cancel_requested = 1,
            error_message = COALESCE(error_message, ?),
            updated_at = ?
        WHERE status = 'active'
        """,
        (reason, now),
    )
    conn.commit()
    return cursor.rowcount


def set_ai_worker_paused(conn, paused):
    """Pause or resume the background AI worker."""
    conn.execute(
        "UPDATE ai_worker_control SET paused = ?, updated_at = ? WHERE id = 1",
        (1 if paused else 0, utc_now()),
    )
    conn.commit()


def ai_worker_paused(conn):
    """Return whether the persistent AI-worker pause flag is enabled."""
    row = conn.execute("SELECT paused FROM ai_worker_control WHERE id = 1").fetchone()
    return bool(row and row["paused"] == 1)


def latest_ai_request_activity(conn, limit=100):
    """Return recent sanitized AI lifecycle records for the Admin console."""
    rows = conn.execute(
        """
        SELECT activity_uid, case_uid, detection_id, comparison_uid,
               anonymous_slot, assessment_type, phase, status, message,
               prompt_chars, prompt_bytes, estimated_tokens, timeout_seconds,
               elapsed_ms, parse_status, error_message, cancel_requested,
               started_at, updated_at,
               CASE
                 WHEN detection_id IS NULL THEN 0
                 WHEN EXISTS (
                   SELECT 1 FROM detections
                   WHERE detections.id = ai_request_activity.detection_id
                 ) THEN 1
                 ELSE 0
               END AS case_available,
               CASE
                 WHEN status = 'active' THEN
                   MAX(0, CAST((julianday('now') - julianday(started_at)) * 86400 AS INTEGER))
                 ELSE
                   MAX(0, CAST((julianday(updated_at) - julianday(started_at)) * 86400 AS INTEGER))
               END AS elapsed_seconds
        FROM ai_request_activity
        ORDER BY CASE status WHEN 'active' THEN 0 ELSE 1 END, id DESC
        LIMIT ?
        """,
        (max(1, min(int(limit), 500)),),
    ).fetchall()
    return [dict(row) for row in rows]


def record_runtime_components(conn, components):
    """Store one launcher heartbeat snapshot for all managed child processes."""
    now = utc_now()
    conn.executemany(
        """
        INSERT INTO runtime_components (
          component, status, pid, required, exit_code, started_at, heartbeat_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(component) DO UPDATE SET
          status = excluded.status,
          pid = excluded.pid,
          required = excluded.required,
          exit_code = excluded.exit_code,
          started_at = COALESCE(excluded.started_at, runtime_components.started_at),
          heartbeat_at = excluded.heartbeat_at
        """,
        [
            (
                item["component"],
                item["status"],
                item.get("pid"),
                1 if item.get("required") else 0,
                item.get("exit_code"),
                item.get("started_at"),
                now,
            )
            for item in components
        ],
    )
    conn.commit()


def latest_runtime_components(conn):
    """Return launcher process state and mark expired heartbeats as stale."""
    rows = conn.execute(
        """
        SELECT component, status, pid, required, exit_code, started_at,
               heartbeat_at,
               MAX(
                 0,
                 CAST((julianday('now') - julianday(heartbeat_at)) * 86400 AS INTEGER)
               ) AS heartbeat_age_seconds
        FROM runtime_components
        ORDER BY required DESC, component ASC
        """
    ).fetchall()
    components = []
    for row in rows:
        item = dict(row)
        if item["status"] == "running" and item["heartbeat_age_seconds"] > 10:
            item["status"] = "stale"
        item["required"] = bool(item["required"])
        components.append(item)
    return components


def create_ai_comparison_run(
    conn,
    case_uid,
    detection_id,
    evidence_sha256,
    prompt_version,
    threat_intel_evidence=None,
    selected_profile_uids=None,
    control_snapshot=None,
    model_inventory=None,
    status="running",
):
    """Save a new AI comparison run."""
    selected_profile_uids = list(selected_profile_uids or [])
    snapshot = control_snapshot or {}
    comparison_uid = new_ai_comparison_uid()
    cur = conn.execute(
        """
        INSERT INTO ai_comparison_runs (
          comparison_uid, case_uid, detection_id, evidence_sha256, prompt_version,
          threat_intel_evidence_json,
          status, candidate_count, expected_candidate_count,
          selected_profile_uids_json, execution_order_json,
          control_temperature, control_seed, control_snapshot_locked_at,
          prompt_text, prompt_sha256, evidence_package_json,
          evidence_manifest_json, omission_manifest_json, source_map_json,
          control_request_options_json, model_inventory_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, 0.0, 42, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            comparison_uid,
            case_uid,
            detection_id,
            evidence_sha256,
            prompt_version,
            json.dumps(threat_intel_evidence or {}, sort_keys=True),
            status,
            len(selected_profile_uids),
            json.dumps(selected_profile_uids),
            json.dumps(selected_profile_uids),
            utc_now(),
            snapshot.get("prompt_text"),
            snapshot.get("prompt_sha256"),
            # Preserve insertion order so controlled variants can replace the
            # exact evidence JSON embedded in the frozen baseline prompt.
            json.dumps(snapshot.get("evidence_package") or {}),
            json.dumps(snapshot.get("evidence_manifest") or {}, sort_keys=True),
            json.dumps(snapshot.get("omission_manifest") or [], sort_keys=True),
            json.dumps(snapshot.get("source_map") or {}, sort_keys=True),
            json.dumps(snapshot.get("request_options") or {}, sort_keys=True),
            json.dumps(model_inventory or {}, sort_keys=True),
        ),
    )
    conn.commit()
    return cur.lastrowid, comparison_uid


def insert_ai_comparison_candidate(conn, comparison_run_id, slot, profile_uid, report=None, error=None):
    """Save one model candidate for an AI comparison."""
    report = report or {}
    status = "failed" if error is not None else "complete"
    cur = conn.execute(
        """
        INSERT INTO ai_comparison_candidates (
          comparison_run_id, anonymous_slot, ai_profile_uid, model_provider,
          model_name, model_identity, model_run_id, prompt_version, prompt_sha256,
          classification, confidence, summary, who_summary,
          what_summary, when_summary, where_summary, why_summary, how_summary,
          next_steps_json, threat_intel_analysis_json, recommended_action,
          raw_response, elapsed_ms, status,
          error_message, evidence_sha256, response_sha256, model_digest,
          model_size, model_quantization, request_options_json,
          response_metrics_json, parse_status
        )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?)
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
            report.get("audit_evidence_sha256"),
            report.get("audit_response_sha256"),
            report.get("model_digest"),
            report.get("model_size"),
            report.get("model_quantization"),
            json.dumps(report.get("audit_request_options") or {}, sort_keys=True),
            json.dumps(report.get("audit_response_metrics") or {}, sort_keys=True),
            report.get("audit_parse_status"),
        ),
    )
    conn.commit()
    return cur.lastrowid


def update_ai_comparison_progress(conn, comparison_run_id):
    """Persist live completion counts while a sequential comparison is running."""
    row = conn.execute(
        """
        SELECT
          SUM(CASE WHEN status = 'complete' THEN 1 ELSE 0 END) AS completed,
          COUNT(*) AS processed
        FROM ai_comparison_candidates
        WHERE comparison_run_id = ?
        """,
        (comparison_run_id,),
    ).fetchone()
    completed = int(row["completed"] or 0)
    processed = int(row["processed"] or 0)
    conn.execute(
        """
        UPDATE ai_comparison_runs
        SET candidate_count = ?, worker_claimed_at = ?
        WHERE id = ?
        """,
        (completed, utc_now(), comparison_run_id),
    )
    conn.commit()
    return {"completed": completed, "processed": processed}


def fail_stale_ai_comparison_runs(conn, max_age_seconds=600):
    """Close runs left in progress by a stopped dashboard process."""
    cutoff = f"-{max(60, int(max_age_seconds))} seconds"
    cur = conn.execute(
        """
        UPDATE ai_comparison_runs
        SET status = 'failed',
            error_message = COALESCE(
              error_message,
              'Comparison interrupted before all model requests completed'
            ),
            completed_at = ?
        WHERE status = 'running'
          AND created_at < datetime('now', ?)
        """,
        (utc_now(), cutoff),
    )
    conn.commit()
    return cur.rowcount


def finish_ai_comparison_run(conn, comparison_run_id, status, candidate_count, error_message=None):
    """Mark a model-comparison run complete or failed."""
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
    """Return analyst votes recorded for one model-comparison run."""
    rows = conn.execute(
        """
        SELECT id, analyst_name, selection, notes, created_at
        FROM ai_comparison_votes
        WHERE comparison_run_id = ?
        ORDER BY id DESC
        """,
        (comparison_run_id,),
    ).fetchall()
    return [without_operational_scores(row) for row in rows]


def ai_comparison_detail(conn, comparison_uid):
    """Return one comparison with candidates, votes, and frozen input metadata."""
    run = conn.execute(
        """
        SELECT id, comparison_uid, case_uid, detection_id, evidence_sha256,
               prompt_version, threat_intel_evidence_json, status,
               candidate_count, expected_candidate_count,
               selected_profile_uids_json, execution_order_json,
               control_temperature, control_seed, control_snapshot_locked_at,
               prompt_sha256, model_inventory_json, error_message,
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
               classification, confidence, summary,
               who_summary, what_summary, when_summary, where_summary,
               why_summary, how_summary, next_steps_json,
               threat_intel_analysis_json, recommended_action,
               raw_response, elapsed_ms, status, error_message, created_at,
               evidence_sha256, response_sha256, model_digest, model_size,
               model_quantization, request_options_json, response_metrics_json,
               parse_status
        FROM ai_comparison_candidates
        WHERE comparison_run_id = ?
        ORDER BY anonymous_slot
        """,
        (result["id"],),
    ).fetchall()
    model_run_ids = [row["model_run_id"] for row in rows if row["model_run_id"]]
    audit_by_run = {}
    if model_run_ids:
        placeholders = ",".join("?" for _item in model_run_ids)
        audit_rows = conn.execute(
            f"""
            SELECT model_run_id, prompt_sha256, evidence_sha256,
                   request_options_json, prepared_at
            FROM ai_run_audits
            WHERE detection_id = ?
              AND model_run_id IN ({placeholders})
            """,
            (result["detection_id"], *model_run_ids),
        ).fetchall()
        for audit_row in audit_rows:
            audit = dict(audit_row)
            try:
                request_options = json.loads(
                    audit.pop("request_options_json") or "{}"
                )
            except (TypeError, json.JSONDecodeError):
                request_options = {}
            audit["request_options"] = request_options
            audit_by_run[audit["model_run_id"]] = audit
    candidates = []
    try:
        result["threat_intel_evidence"] = json.loads(
            result.pop("threat_intel_evidence_json") or "{}"
        )
    except (TypeError, ValueError):
        result["threat_intel_evidence"] = {}
    for source, target, fallback in (
        ("selected_profile_uids_json", "selected_profile_uids", []),
        ("execution_order_json", "execution_order", []),
        ("model_inventory_json", "model_inventory", {}),
    ):
        try:
            result[target] = json.loads(result.pop(source) or json.dumps(fallback))
        except (TypeError, ValueError):
            result[target] = fallback
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
        for source, target in (
            ("request_options_json", "request_options"),
            ("response_metrics_json", "response_metrics"),
        ):
            try:
                item[target] = json.loads(item.pop(source) or "{}")
            except (TypeError, ValueError):
                item[target] = {}
        item["input_audit"] = audit_by_run.get(item.get("model_run_id")) or {}
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
        candidates.append(without_operational_scores(item))
    result["candidate_count"] = sum(
        1 for candidate in candidates if candidate.get("status") == "complete"
    )
    result["processed_count"] = len(candidates)
    result["candidates"] = candidates
    result["votes"] = votes
    vote = votes[0] if votes else None
    result["identities_revealed"] = bool(vote)
    selected_candidate = None
    valid_slots = {item.get("anonymous_slot") for item in candidates}
    if vote and vote.get("selection") in valid_slots:
        selected_candidate = next(
            (
                item
                for item in candidates
                if item.get("anonymous_slot") == vote.get("selection")
            ),
            None,
        )
    result["review_outcome"] = {
        "status": (
            "winner_selected"
            if selected_candidate
            else "rejected"
            if vote and vote.get("selection") == "reject_all"
            else "tie"
            if vote and vote.get("selection") == "tie"
            else "awaiting_review"
        ),
        "selection": vote.get("selection") if vote else None,
        "analyst_name": vote.get("analyst_name") if vote else None,
        "reviewed_at": vote.get("created_at") if vote else None,
        "winner": (
            {
                "anonymous_slot": selected_candidate.get("anonymous_slot"),
                "ai_profile_uid": selected_candidate.get("ai_profile_uid"),
                "model_provider": selected_candidate.get("model_provider"),
                "model_name": selected_candidate.get("model_name"),
                "model_identity": selected_candidate.get("model_identity"),
            }
            if selected_candidate
            else None
        ),
    }
    if not vote:
        for candidate in candidates:
            candidate["model_provider"] = None
            candidate["model_name"] = None
            candidate["model_identity"] = None
            candidate["model_digest"] = None
            candidate["model_size"] = None
            candidate["model_quantization"] = None
    promoted = conn.execute(
        """
        SELECT promotions.analyst_name, promotions.notes, promotions.created_at,
               candidates.anonymous_slot, candidates.ai_profile_uid,
               candidates.model_provider, candidates.model_name,
               candidates.model_identity
        FROM ai_case_explanation_promotions AS promotions
        JOIN ai_comparison_candidates AS candidates
          ON candidates.id = promotions.candidate_id
        WHERE promotions.comparison_run_id = ?
        ORDER BY promotions.id DESC
        LIMIT 1
        """,
        (result["id"],),
    ).fetchone()
    active_promotion = conn.execute(
        """
        SELECT runs.comparison_uid, candidates.anonymous_slot,
               candidates.model_identity, promotions.created_at
        FROM ai_case_explanation_promotions AS promotions
        JOIN ai_comparison_runs AS runs
          ON runs.id = promotions.comparison_run_id
        JOIN ai_comparison_candidates AS candidates
          ON candidates.id = promotions.candidate_id
        WHERE promotions.detection_id = ?
        ORDER BY promotions.id DESC
        LIMIT 1
        """,
        (result["detection_id"],),
    ).fetchone()
    result["case_explanation_promotion"] = dict(promoted) if promoted else None
    result["active_case_explanation"] = (
        dict(active_promotion) if active_promotion else None
    )
    completed_inputs = [
        item.get("input_audit") or {}
        for item in candidates
        if item.get("status") == "complete"
    ]
    prompt_hashes = {
        item.get("prompt_sha256")
        for item in completed_inputs
        if item.get("prompt_sha256")
    }
    evidence_hashes = {
        item.get("evidence_sha256")
        for item in completed_inputs
        if item.get("evidence_sha256")
    }
    generation_options = {
        json.dumps(
            (item.get("request_options") or {}).get("options") or {},
            sort_keys=True,
        )
        for item in completed_inputs
    }
    initial_snapshot = initial_ai_request_snapshot(conn, result["detection_id"])
    initial_prompt_hash = (
        initial_snapshot.get("prompt_sha256") if initial_snapshot else None
    )
    initial_evidence_hash = (
        initial_snapshot.get("evidence_sha256") if initial_snapshot else None
    )
    result["input_consistency"] = {
        "candidate_count_with_audit": len(completed_inputs),
        "same_prompt_across_candidates": (
            bool(completed_inputs) and len(prompt_hashes) == 1
        ),
        "same_evidence_across_candidates": (
            bool(completed_inputs) and len(evidence_hashes) == 1
        ),
        "same_generation_options_across_candidates": (
            bool(completed_inputs) and len(generation_options) == 1
        ),
        "prompt_sha256": next(iter(prompt_hashes), None)
        if len(prompt_hashes) == 1
        else None,
        "evidence_sha256": next(iter(evidence_hashes), None)
        if len(evidence_hashes) == 1
        else None,
        "matches_initial_case_prompt": (
            len(prompt_hashes) == 1
            and initial_prompt_hash is not None
            and next(iter(prompt_hashes)) == initial_prompt_hash
        ),
        "matches_initial_case_evidence": (
            len(evidence_hashes) == 1
            and initial_evidence_hash is not None
            and next(iter(evidence_hashes)) == initial_evidence_hash
        ),
        "initial_prompt_sha256": initial_prompt_hash,
        "initial_evidence_sha256": initial_evidence_hash,
        "initial_prepared_at": (
            initial_snapshot.get("prepared_at") if initial_snapshot else None
        ),
    }
    result.pop("id", None)
    return result


def list_ai_comparison_runs(conn, limit=50, case_uid=None):
    """List saved AI comparison runs."""
    params = []
    where = ""
    if case_uid:
        where = "WHERE runs.case_uid = ?"
        params.append(case_uid)
    params.append(int(limit))
    rows = conn.execute(
        f"""
        SELECT runs.comparison_uid, runs.case_uid, runs.detection_id,
               runs.status, runs.expected_candidate_count,
               (
                 SELECT COUNT(*)
                 FROM ai_comparison_candidates AS completed_candidates
                 WHERE completed_candidates.comparison_run_id = runs.id
                   AND completed_candidates.status = 'complete'
               ) AS candidate_count,
               (
                 SELECT COUNT(*)
                 FROM ai_comparison_candidates AS processed_candidates
                 WHERE processed_candidates.comparison_run_id = runs.id
               ) AS processed_count,
               runs.created_at, runs.completed_at,
               COUNT(votes.id) AS vote_count,
               MAX(votes.selection) AS selection,
               MAX(votes.analyst_name) AS analyst_name,
               MAX(votes.created_at) AS reviewed_at
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
    """Record an analyst selection or reject-all decision for a comparison."""
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
    candidate_slots = {
        row["anonymous_slot"]
        for row in conn.execute(
            """
            SELECT anonymous_slot FROM ai_comparison_candidates
            WHERE comparison_run_id = ? AND status = 'complete'
            """,
            (run["id"],),
        ).fetchall()
    }
    if selection not in candidate_slots | {"tie", "reject_all"}:
        raise ValueError(
            "Selection must identify an available response, tie, or reject_all"
        )
    if selection in candidate_slots:
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


def promote_ai_comparison_winner(conn, comparison_uid, analyst_name="", notes=""):
    """Make the reviewed winner the case's displayed AI explanation.

    The comparison candidate and original AI report remain immutable. A new
    promotion row records the analyst's presentation choice, and the latest
    promotion for a detection becomes the explanation shown on its case page.
    """
    row = conn.execute(
        """
        SELECT runs.id AS comparison_run_id, runs.detection_id, runs.case_uid,
               votes.analyst_name AS reviewing_analyst,
               votes.selection, candidates.id AS candidate_id
        FROM ai_comparison_runs AS runs
        JOIN ai_comparison_votes AS votes
          ON votes.comparison_run_id = runs.id
        LEFT JOIN ai_comparison_candidates AS candidates
          ON candidates.comparison_run_id = runs.id
         AND candidates.anonymous_slot = votes.selection
         AND candidates.status = 'complete'
        WHERE runs.comparison_uid = ?
        """,
        (comparison_uid,),
    ).fetchone()
    if not row:
        raise ValueError("Select a comparison winner before using it on the case")
    if row["selection"] in {"tie", "reject_all"} or not row["candidate_id"]:
        raise ValueError("Only a completed winning response can be used on the case")
    conn.execute(
        """
        INSERT INTO ai_case_explanation_promotions (
          detection_id, case_uid, comparison_run_id, candidate_id,
          analyst_name, notes, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            row["detection_id"],
            row["case_uid"],
            row["comparison_run_id"],
            row["candidate_id"],
            (analyst_name or row["reviewing_analyst"] or "analyst").strip(),
            (notes or "").strip(),
            utc_now(),
        ),
    )
    conn.commit()
    return True


def selected_case_explanation(conn, detection_id):
    """Return the latest analyst-promoted comparison response for a case."""
    row = conn.execute(
        """
        SELECT promotions.analyst_name AS selected_by,
               promotions.notes AS selection_notes,
               promotions.created_at AS selected_at,
               runs.comparison_uid,
               candidates.anonymous_slot,
               candidates.ai_profile_uid,
               candidates.model_provider,
               candidates.model_name,
               candidates.model_identity,
               candidates.model_run_id,
               candidates.prompt_version,
               candidates.classification,
               candidates.confidence,
               candidates.summary,
               candidates.who_summary,
               candidates.what_summary,
               candidates.when_summary,
               candidates.where_summary,
               candidates.why_summary,
               candidates.how_summary,
               candidates.next_steps_json,
               candidates.threat_intel_analysis_json,
               candidates.recommended_action,
               candidates.raw_response,
               candidates.elapsed_ms
        FROM ai_case_explanation_promotions AS promotions
        JOIN ai_comparison_runs AS runs
          ON runs.id = promotions.comparison_run_id
        JOIN ai_comparison_candidates AS candidates
          ON candidates.id = promotions.candidate_id
        WHERE promotions.detection_id = ?
        ORDER BY promotions.id DESC
        LIMIT 1
        """,
        (detection_id,),
    ).fetchone()
    if not row:
        return None
    result = dict(row)
    try:
        result["next_steps"] = json.loads(result.pop("next_steps_json") or "[]")
    except (TypeError, json.JSONDecodeError):
        result["next_steps"] = []
    try:
        result["threat_intel_analysis"] = json.loads(
            result.pop("threat_intel_analysis_json") or "{}"
        )
    except (TypeError, json.JSONDecodeError):
        result["threat_intel_analysis"] = {}
    return without_operational_scores(result)


def reopen_ai_comparison_review(conn, comparison_uid):
    """Archive and remove the current vote so the comparison can be reviewed again."""
    run = conn.execute(
        "SELECT id FROM ai_comparison_runs WHERE comparison_uid = ?",
        (comparison_uid,),
    ).fetchone()
    if not run:
        return False
    vote = conn.execute(
        """
        SELECT id, analyst_name, selection, notes, created_at
        FROM ai_comparison_votes
        WHERE comparison_run_id = ?
        LIMIT 1
        """,
        (run["id"],),
    ).fetchone()
    if not vote:
        raise ValueError("This comparison has not been reviewed")
    conn.execute(
        """
        INSERT INTO ai_comparison_review_history (
          comparison_run_id, analyst_name, selection, notes, reviewed_at, reopened_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            run["id"],
            vote["analyst_name"],
            vote["selection"],
            vote["notes"],
            vote["created_at"],
            utc_now(),
        ),
    )
    conn.execute("DELETE FROM ai_comparison_votes WHERE id = ?", (vote["id"],))
    conn.commit()
    return True


def ai_comparison_selection_summary(conn):
    """Aggregate reviewed comparison selections by anonymous candidate model."""
    rows = conn.execute(
        """
        SELECT candidates.ai_profile_uid, candidates.model_provider,
               candidates.model_name, candidates.model_identity,
               COUNT(votes.id) AS wins
        FROM ai_comparison_votes AS votes
        JOIN ai_comparison_candidates AS candidates
          ON candidates.comparison_run_id = votes.comparison_run_id
         AND candidates.anonymous_slot = votes.selection
        WHERE votes.selection NOT IN ('tie', 'reject_all')
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
    run_totals = conn.execute(
        """
        SELECT COUNT(*) AS runs,
               COUNT(DISTINCT case_uid) AS cases,
               SUM(CASE WHEN status = 'complete' THEN 1 ELSE 0 END) AS complete,
               SUM(CASE WHEN status = 'partial' THEN 1 ELSE 0 END) AS partial,
               SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed
        FROM ai_comparison_runs
        """
    ).fetchone()
    pending = conn.execute(
        """
        SELECT COUNT(*) AS pending
        FROM ai_comparison_runs AS runs
        WHERE NOT EXISTS (
          SELECT 1 FROM ai_comparison_votes AS votes
          WHERE votes.comparison_run_id = runs.id
        )
        """
    ).fetchone()
    reviewed_cases = conn.execute(
        """
        SELECT COUNT(DISTINCT runs.case_uid) AS count
        FROM ai_comparison_runs AS runs
        JOIN ai_comparison_votes AS votes
          ON votes.comparison_run_id = runs.id
        """
    ).fetchone()
    reopened = conn.execute(
        "SELECT COUNT(*) AS count FROM ai_comparison_review_history"
    ).fetchone()
    return {
        "models": [dict(row) for row in rows],
        "votes": int(totals["votes"] or 0),
        "ties": int(totals["ties"] or 0),
        "rejected": int(totals["rejected"] or 0),
        "runs": int(run_totals["runs"] or 0),
        "cases": int(run_totals["cases"] or 0),
        "complete": int(run_totals["complete"] or 0),
        "partial": int(run_totals["partial"] or 0),
        "failed": int(run_totals["failed"] or 0),
        "pending": int(pending["pending"] or 0),
        "reviewed_cases": int(reviewed_cases["count"] or 0),
        "reopened_reviews": int(reopened["count"] or 0),
    }


def ai_comparison_export_rows(conn):
    """Return one research-friendly row per comparison run."""
    rows = conn.execute(
        """
        SELECT runs.comparison_uid, runs.case_uid, runs.detection_id,
               runs.status AS run_status, runs.created_at, runs.completed_at,
               CASE
                 WHEN runs.completed_at IS NOT NULL THEN
                   ROUND(
                     MAX(
                       0,
                       (julianday(runs.completed_at) - julianday(runs.created_at))
                       * 86400
                     ),
                     3
                   )
                 ELSE NULL
               END AS comparison_wall_clock_seconds,
               runs.evidence_sha256, runs.prompt_version,
               votes.selection, votes.analyst_name, votes.notes AS review_notes,
               votes.created_at AS reviewed_at
        FROM ai_comparison_runs AS runs
        LEFT JOIN ai_comparison_votes AS votes
          ON votes.comparison_run_id = runs.id
        ORDER BY runs.id DESC
        """
    ).fetchall()
    exported = []
    for row in rows:
        item = dict(row)
        candidates = conn.execute(
            """
            SELECT candidates.anonymous_slot, candidates.ai_profile_uid,
                   candidates.model_provider, candidates.model_name,
                   candidates.model_identity, candidates.classification,
                   candidates.confidence, candidates.status,
                   candidates.elapsed_ms, candidates.prompt_sha256,
                   (
                     SELECT audits.evidence_sha256
                     FROM ai_run_audits AS audits
                     WHERE audits.model_run_id = candidates.model_run_id
                     ORDER BY audits.id DESC
                     LIMIT 1
                   ) AS evidence_sha256
            FROM ai_comparison_candidates AS candidates
            WHERE candidates.comparison_run_id = (
              SELECT id FROM ai_comparison_runs WHERE comparison_uid = ?
            )
            ORDER BY candidates.anonymous_slot
            """,
            (item["comparison_uid"],),
        ).fetchall()
        item["review_status"] = (
            "rejected"
            if item.get("selection") == "reject_all"
            else "tie"
            if item.get("selection") == "tie"
            else "reviewed"
            if item.get("selection")
            else "pending"
        )
        available_slots = {
            candidate_row["anonymous_slot"] for candidate_row in candidates
        }
        item["selected_response"] = (
            item.get("selection")
            if item.get("selection") in available_slots
            else None
        )
        selected = None
        completed_elapsed_ms = []
        for candidate_row in candidates:
            candidate = dict(candidate_row)
            slot = candidate.pop("anonymous_slot")
            for key, value in candidate.items():
                item[f"response_{slot.lower()}_{key}"] = value
            elapsed_ms = candidate.get("elapsed_ms")
            item[f"response_{slot.lower()}_elapsed_seconds"] = (
                round(float(elapsed_ms) / 1000, 3)
                if elapsed_ms is not None
                else None
            )
            if candidate.get("status") == "complete" and elapsed_ms is not None:
                completed_elapsed_ms.append(float(elapsed_ms))
            if slot == item.get("selected_response"):
                selected = candidate
        item["selected_profile_uid"] = (
            selected.get("ai_profile_uid") if selected else None
        )
        item["selected_model_identity"] = (
            selected.get("model_identity") if selected else None
        )
        item["selected_response_elapsed_ms"] = (
            selected.get("elapsed_ms") if selected else None
        )
        item["selected_response_elapsed_seconds"] = (
            round(float(selected["elapsed_ms"]) / 1000, 3)
            if selected and selected.get("elapsed_ms") is not None
            else None
        )
        item["successful_response_total_elapsed_ms"] = (
            int(round(sum(completed_elapsed_ms))) if completed_elapsed_ms else None
        )
        item["successful_response_total_elapsed_seconds"] = (
            round(sum(completed_elapsed_ms) / 1000, 3)
            if completed_elapsed_ms
            else None
        )
        item["successful_response_average_elapsed_ms"] = (
            round(sum(completed_elapsed_ms) / len(completed_elapsed_ms), 3)
            if completed_elapsed_ms
            else None
        )
        item["successful_response_average_elapsed_seconds"] = (
            round(sum(completed_elapsed_ms) / len(completed_elapsed_ms) / 1000, 3)
            if completed_elapsed_ms
            else None
        )
        initial_snapshot = initial_ai_request_snapshot(conn, item["detection_id"])
        item["initial_prompt_sha256"] = (
            initial_snapshot.get("prompt_sha256") if initial_snapshot else None
        )
        item["initial_evidence_sha256"] = (
            initial_snapshot.get("evidence_sha256") if initial_snapshot else None
        )
        item["initial_prompt_version"] = (
            initial_snapshot.get("prompt_version") if initial_snapshot else None
        )
        completed_candidates = [
            dict(candidate_row)
            for candidate_row in candidates
            if candidate_row["status"] == "complete"
        ]
        candidate_prompt_hashes = {
            candidate.get("prompt_sha256")
            for candidate in completed_candidates
            if candidate.get("prompt_sha256")
        }
        candidate_evidence_hashes = {
            candidate.get("evidence_sha256")
            for candidate in completed_candidates
            if candidate.get("evidence_sha256")
        }
        item["same_prompt_across_candidates"] = (
            bool(completed_candidates) and len(candidate_prompt_hashes) == 1
        )
        item["same_evidence_across_candidates"] = (
            bool(completed_candidates) and len(candidate_evidence_hashes) == 1
        )
        item["matches_initial_prompt"] = (
            len(candidate_prompt_hashes) == 1
            and item["initial_prompt_sha256"] is not None
            and next(iter(candidate_prompt_hashes)) == item["initial_prompt_sha256"]
        )
        item["matches_initial_evidence"] = (
            len(candidate_evidence_hashes) == 1
            and item["initial_evidence_sha256"] is not None
            and next(iter(candidate_evidence_hashes)) == item["initial_evidence_sha256"]
        )
        if (
            len(candidate_prompt_hashes) == 1
            and item.get("evidence_sha256") in candidate_prompt_hashes
            and candidate_evidence_hashes
            and item.get("evidence_sha256") not in candidate_evidence_hashes
        ):
            item["comparison_run_hash_type"] = (
                "legacy_prompt_hash_mislabeled_as_evidence"
            )
        elif (
            len(candidate_evidence_hashes) == 1
            and item.get("evidence_sha256") in candidate_evidence_hashes
        ):
            item["comparison_run_hash_type"] = "evidence_package_sha256"
        else:
            item["comparison_run_hash_type"] = "unknown_or_incomplete"
        history = conn.execute(
            """
            SELECT analyst_name, selection, notes, reviewed_at, reopened_at
            FROM ai_comparison_review_history
            WHERE comparison_run_id = (
              SELECT id FROM ai_comparison_runs WHERE comparison_uid = ?
            )
            ORDER BY id
            """,
            (item["comparison_uid"],),
        ).fetchall()
        item["reopened_review_count"] = len(history)
        item["review_history_json"] = json.dumps(
            [dict(history_row) for history_row in history],
            sort_keys=True,
        )
        exported.append(item)
    return exported


def ai_comparison_candidate_export_rows(conn):
    """Return one stable research row per candidate, regardless of run size."""
    rows = conn.execute(
        """
        SELECT runs.comparison_uid, runs.case_uid, runs.detection_id,
               runs.status AS run_status, runs.expected_candidate_count,
               runs.control_temperature, runs.control_seed,
               runs.created_at AS run_created_at,
               runs.completed_at AS run_completed_at,
               candidates.anonymous_slot AS response_label,
               candidates.ai_profile_uid, candidates.model_provider,
               candidates.model_name, candidates.model_identity,
               candidates.model_digest, candidates.model_size,
               candidates.model_quantization, candidates.model_run_id,
               candidates.prompt_version, candidates.prompt_sha256,
               candidates.evidence_sha256, candidates.response_sha256,
               candidates.classification, candidates.confidence,
               candidates.summary, candidates.who_summary,
               candidates.what_summary, candidates.when_summary,
               candidates.where_summary, candidates.why_summary,
               candidates.how_summary, candidates.next_steps_json,
               candidates.recommended_action, candidates.raw_response,
               candidates.elapsed_ms, candidates.status,
               candidates.error_message, candidates.parse_status,
               candidates.request_options_json,
               candidates.response_metrics_json,
               candidates.created_at AS candidate_created_at,
               votes.selection AS review_selection,
               votes.analyst_name, votes.notes AS review_notes,
               votes.created_at AS reviewed_at
        FROM ai_comparison_runs AS runs
        JOIN ai_comparison_candidates AS candidates
          ON candidates.comparison_run_id = runs.id
        LEFT JOIN ai_comparison_votes AS votes
          ON votes.comparison_run_id = runs.id
        ORDER BY runs.id, candidates.id
        """
    ).fetchall()
    exported = []
    for row in rows:
        item = dict(row)
        try:
            request = json.loads(item.pop("request_options_json") or "{}")
        except (TypeError, ValueError):
            request = {}
        try:
            metrics = json.loads(item.pop("response_metrics_json") or "{}")
        except (TypeError, ValueError):
            metrics = {}
        try:
            next_steps = json.loads(item.pop("next_steps_json") or "[]")
        except (TypeError, ValueError):
            next_steps = []
        options = request.get("options") or request
        selection = item.get("review_selection")
        item["review_outcome"] = (
            "winner"
            if selection == item["response_label"]
            else "tie"
            if selection == "tie"
            else "reject_all"
            if selection == "reject_all"
            else "not_selected"
            if selection
            else "pending"
        )
        item["temperature"] = options.get(
            "temperature", item.get("control_temperature")
        )
        item["seed"] = options.get("seed", item.get("control_seed"))
        item["num_ctx"] = options.get("num_ctx")
        item["num_predict"] = options.get("num_predict")
        item["prompt_token_count"] = metrics.get("prompt_eval_count")
        item["generated_token_count"] = metrics.get("eval_count")
        item["total_duration_ns"] = metrics.get("total_duration")
        item["load_duration_ns"] = metrics.get("load_duration")
        item["prompt_eval_duration_ns"] = metrics.get("prompt_eval_duration")
        item["eval_duration_ns"] = metrics.get("eval_duration")
        item["next_steps"] = json.dumps(next_steps, ensure_ascii=True)
        exported.append(item)
    return exported


def list_ai_profiles(conn, limit=100):
    """List saved AI model profiles."""
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


# ---------------------------------------------------------------------------
# Persistent LLM experiment queue
# ---------------------------------------------------------------------------

def new_ai_experiment_uid(prefix="EXP"):
    """Create a unique ID for an AI experiment."""
    return f"{prefix}-{datetime.now(timezone.utc):%Y%m%d}-{uuid.uuid4().hex[:12]}"


def create_ai_experiment_run(
    conn,
    experiment_type,
    parent_comparison_uid,
    case_uid,
    detection_id,
    configuration,
    tasks,
    parent_winner_candidate_id=None,
):
    """Create a queued run and all tasks atomically."""
    experiment_uid = new_ai_experiment_uid(
        "STAB" if experiment_type == "sampling_stability" else "MISS"
    )
    with conn:
        cur = conn.execute(
            """
            INSERT INTO ai_experiment_runs (
              experiment_uid, experiment_type, parent_comparison_uid,
              parent_winner_candidate_id, case_uid, detection_id, status,
              total_task_count, configuration_json
            ) VALUES (?, ?, ?, ?, ?, ?, 'queued', ?, ?)
            """,
            (
                experiment_uid,
                experiment_type,
                parent_comparison_uid,
                parent_winner_candidate_id,
                case_uid,
                detection_id,
                len(tasks),
                json.dumps(configuration or {}, sort_keys=True),
            ),
        )
        run_id = cur.lastrowid
        for task in tasks:
            conn.execute(
                """
                INSERT INTO ai_experiment_results (
                  result_uid, experiment_run_id, baseline_candidate_id,
                  ai_profile_uid, anonymous_label, model_provider, model_name,
                  model_identity, model_digest, model_size, model_quantization,
                  variant_label, temperature, seed, evidence_mask_json,
                  parent_prompt_sha256, parent_evidence_sha256,
                  parent_response_sha256, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'queued')
                """,
                (
                    new_ai_experiment_uid("RES"),
                    run_id,
                    task["baseline_candidate_id"],
                    task["ai_profile_uid"],
                    task["anonymous_label"],
                    task.get("model_provider"),
                    task.get("model_name"),
                    task.get("model_identity"),
                    task.get("model_digest"),
                    task.get("model_size"),
                    task.get("model_quantization"),
                    task["variant_label"],
                    float(task["temperature"]),
                    int(task["seed"]),
                    json.dumps(task.get("evidence_mask") or [], sort_keys=True),
                    task.get("parent_prompt_sha256"),
                    task.get("parent_evidence_sha256"),
                    task.get("parent_response_sha256"),
                ),
            )
    return experiment_uid


def claim_next_ai_experiment_task(conn, stale_seconds=600):
    """Transactionally claim one task so concurrent workers cannot duplicate it."""
    cutoff = f"-{max(60, int(stale_seconds))} seconds"
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute(
            """
            UPDATE ai_experiment_results
            SET status = 'queued', worker_claimed_at = NULL, started_at = NULL
            WHERE status = 'running'
              AND datetime(worker_claimed_at) < datetime('now', ?)
            """,
            (cutoff,),
        )
        row = conn.execute(
            """
            SELECT results.*, runs.experiment_uid, runs.experiment_type,
                   runs.parent_comparison_uid, runs.case_uid, runs.detection_id,
                   runs.configuration_json
            FROM ai_experiment_results AS results
            JOIN ai_experiment_runs AS runs ON runs.id = results.experiment_run_id
            WHERE results.status = 'queued'
              AND runs.status IN ('queued', 'running', 'partial')
            ORDER BY runs.id, results.id
            LIMIT 1
            """
        ).fetchone()
        if not row:
            conn.commit()
            return None
        now = utc_now()
        changed = conn.execute(
            """
            UPDATE ai_experiment_results
            SET status = 'running', worker_claimed_at = ?, started_at = COALESCE(started_at, ?)
            WHERE id = ? AND status = 'queued'
            """,
            (now, now, row["id"]),
        ).rowcount
        if changed != 1:
            conn.rollback()
            return None
        conn.execute(
            """
            UPDATE ai_experiment_runs
            SET status = 'running', started_at = COALESCE(started_at, ?),
                worker_claimed_at = ?
            WHERE id = ?
            """,
            (now, now, row["experiment_run_id"]),
        )
        conn.commit()
        item = dict(row)
        item["configuration"] = json.loads(item.pop("configuration_json") or "{}")
        item["evidence_mask"] = json.loads(item.pop("evidence_mask_json") or "[]")
        return item
    except Exception:
        conn.rollback()
        raise


def finish_ai_experiment_result(conn, result_id, report=None, error=None):
    """Save the final status and measurements for one experiment result."""
    report = report or {}
    status = "failed" if error is not None else "complete"
    conn.execute(
        """
        UPDATE ai_experiment_results
        SET prompt_text = ?, prompt_sha256 = ?, evidence_package_json = ?,
            evidence_sha256 = ?, response_sha256 = ?, classification = ?,
            confidence = ?, summary = ?, who_summary = ?, what_summary = ?,
            when_summary = ?, where_summary = ?, why_summary = ?, how_summary = ?,
            next_steps_json = ?, recommended_action = ?, raw_response = ?,
            request_options_json = ?, response_metrics_json = ?, elapsed_ms = ?,
            parse_status = ?, status = ?, error_message = ?, completed_at = ?
        WHERE id = ?
        """,
        (
            report.get("audit_prompt_text"),
            report.get("prompt_sha256"),
            json.dumps(report.get("audit_evidence_package") or {}, sort_keys=True),
            report.get("audit_evidence_sha256"),
            report.get("audit_response_sha256"),
            report.get("classification"),
            report.get("confidence"),
            report.get("summary"),
            report.get("who"),
            report.get("what"),
            report.get("when"),
            report.get("where"),
            report.get("why"),
            report.get("how"),
            json.dumps(report.get("next_steps") or []),
            report.get("recommended_action"),
            report.get("raw_response"),
            json.dumps(report.get("audit_request_options") or {}, sort_keys=True),
            json.dumps(report.get("audit_response_metrics") or {}, sort_keys=True),
            int(report.get("elapsed_ms") or 0),
            report.get("audit_parse_status"),
            status,
            str(error) if error else None,
            utc_now(),
            result_id,
        ),
    )
    run_id = conn.execute(
        "SELECT experiment_run_id FROM ai_experiment_results WHERE id = ?",
        (result_id,),
    ).fetchone()["experiment_run_id"]
    counts = conn.execute(
        """
        SELECT COUNT(*) AS total,
               SUM(status = 'complete') AS complete,
               SUM(status = 'failed') AS failed,
               SUM(status IN ('queued', 'running')) AS remaining
        FROM ai_experiment_results WHERE experiment_run_id = ?
        """,
        (run_id,),
    ).fetchone()
    remaining = int(counts["remaining"] or 0)
    complete = int(counts["complete"] or 0)
    failed = int(counts["failed"] or 0)
    run_status = (
        "running"
        if remaining
        else "complete"
        if complete and not failed
        else "partial"
        if complete
        else "failed"
    )
    conn.execute(
        """
        UPDATE ai_experiment_runs
        SET status = ?, completed_task_count = ?, failed_task_count = ?,
            completed_at = CASE WHEN ? = 0 THEN ? ELSE completed_at END
        WHERE id = ?
        """,
        (run_status, complete, failed, remaining, utc_now(), run_id),
    )
    conn.commit()


def list_ai_experiment_runs(conn, experiment_type=None, limit=100):
    """List saved AI experiment runs."""
    where = "WHERE experiment_type = ?" if experiment_type else ""
    params = [experiment_type] if experiment_type else []
    params.append(int(limit))
    rows = conn.execute(
        f"""
        SELECT experiment_uid, experiment_type, parent_comparison_uid, case_uid,
               status, total_task_count, completed_task_count, failed_task_count,
               configuration_json, created_at, started_at, completed_at,
               error_summary
        FROM ai_experiment_runs {where}
        ORDER BY id DESC LIMIT ?
        """,
        tuple(params),
    ).fetchall()
    results = []
    for row in rows:
        item = dict(row)
        item["configuration"] = json.loads(item.pop("configuration_json") or "{}")
        results.append(item)
    return results


def ai_experiment_detail(conn, experiment_uid):
    """Load one AI experiment and its results."""
    run = conn.execute(
        "SELECT * FROM ai_experiment_runs WHERE experiment_uid = ?",
        (experiment_uid,),
    ).fetchone()
    if not run:
        return None
    item = dict(run)
    item["configuration"] = json.loads(item.pop("configuration_json") or "{}")
    rows = conn.execute(
        """
        SELECT results.*,
               baseline.classification AS baseline_classification,
               baseline.confidence AS baseline_confidence,
               baseline.summary AS baseline_summary,
               baseline.next_steps_json AS baseline_next_steps_json,
               baseline.raw_response AS baseline_raw_response,
               baseline.model_digest AS baseline_model_digest
        FROM ai_experiment_results AS results
        JOIN ai_comparison_candidates AS baseline
          ON baseline.id = results.baseline_candidate_id
        WHERE results.experiment_run_id = ? ORDER BY results.id
        """,
        (item["id"],),
    ).fetchall()
    parsed = []
    for row in rows:
        result = dict(row)
        for source, target, fallback in (
            ("evidence_mask_json", "evidence_mask", []),
            ("evidence_package_json", "evidence_package", {}),
            ("next_steps_json", "next_steps", []),
            ("request_options_json", "request_options", {}),
            ("response_metrics_json", "response_metrics", {}),
            ("baseline_next_steps_json", "baseline_next_steps", []),
        ):
            try:
                result[target] = json.loads(result.pop(source) or json.dumps(fallback))
            except (TypeError, ValueError):
                result[target] = fallback
        parsed.append(result)
    item["results"] = parsed
    item.pop("id", None)
    return item


def ai_experiment_export_rows(conn, experiment_type=None):
    """Build rows for an AI experiment export."""
    rows = conn.execute(
        """
        SELECT runs.experiment_uid, runs.experiment_type,
               runs.parent_comparison_uid, runs.case_uid, runs.detection_id,
               baseline.classification AS baseline_classification,
               baseline.confidence AS baseline_confidence,
               baseline.summary AS baseline_summary,
               baseline.next_steps_json AS baseline_next_steps_json,
               results.*
        FROM ai_experiment_runs AS runs
        JOIN ai_experiment_results AS results
          ON results.experiment_run_id = runs.id
        JOIN ai_comparison_candidates AS baseline
          ON baseline.id = results.baseline_candidate_id
        WHERE (? IS NULL OR runs.experiment_type = ?)
        ORDER BY runs.id, results.id
        """,
        (experiment_type, experiment_type),
    ).fetchall()
    exported = []
    for row in rows:
        item = dict(row)
        item.pop("id", None)
        item.pop("experiment_run_id", None)
        item["removed_evidence"] = ", ".join(
            json.loads(item.get("evidence_mask_json") or "[]")
        )
        try:
            request_options = json.loads(item.get("request_options_json") or "{}")
        except (TypeError, ValueError):
            request_options = {}
        try:
            response_metrics = json.loads(item.get("response_metrics_json") or "{}")
        except (TypeError, ValueError):
            response_metrics = {}
        generation_options = request_options.get("options") or request_options
        item["request_num_ctx"] = generation_options.get("num_ctx")
        item["request_num_predict"] = generation_options.get("num_predict")
        item["request_temperature"] = generation_options.get("temperature")
        item["request_seed"] = generation_options.get("seed")
        item["model_prompt_eval_count"] = response_metrics.get("prompt_eval_count")
        item["model_eval_count"] = response_metrics.get("eval_count")
        item["model_total_duration_ns"] = response_metrics.get("total_duration")
        item["model_load_duration_ns"] = response_metrics.get("load_duration")
        item["model_prompt_eval_duration_ns"] = response_metrics.get(
            "prompt_eval_duration"
        )
        item["model_eval_duration_ns"] = response_metrics.get("eval_duration")
        exported.append(item)
    return exported


def review_ai_experiment_result(conn, result_uid, review):
    """Store human evaluation without changing any operational case record."""
    fields = (
        "grounding_score",
        "completeness_score",
        "next_step_quality_score",
        "uncertainty_score",
        "usefulness_score",
    )
    values = []
    for field in fields:
        value = review.get(field)
        if value is not None and not 0 <= int(value) <= 5:
            raise ValueError(f"{field} must be between 0 and 5")
        values.append(int(value) if value is not None else None)
    count_fields = (
        "supported_claims",
        "unsupported_claims",
        "contradicted_claims",
        "undecidable_claims",
    )
    for field in count_fields:
        value = review.get(field)
        if value is not None and int(value) < 0:
            raise ValueError(f"{field} cannot be negative")
        values.append(int(value) if value is not None else None)
    values.extend(
        [
            1 if review.get("missing_evidence_acknowledged") else 0,
            str(review.get("reviewer_name") or "analyst").strip(),
            str(review.get("reviewer_notes") or "").strip(),
            utc_now(),
            result_uid,
        ]
    )
    changed = conn.execute(
        """
        UPDATE ai_experiment_results
        SET grounding_score = ?, completeness_score = ?,
            next_step_quality_score = ?, uncertainty_score = ?,
            usefulness_score = ?, supported_claims = ?,
            unsupported_claims = ?, contradicted_claims = ?,
            undecidable_claims = ?, missing_evidence_acknowledged = ?,
            reviewer_name = ?, reviewer_notes = ?, reviewed_at = ?
        WHERE result_uid = ?
        """,
        tuple(values),
    ).rowcount
    conn.commit()
    return changed > 0


def get_ai_profile(conn, uid):
    """Load one saved AI model profile."""
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
    """Save a new AI model profile."""
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
    """Update a saved AI model profile."""
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
    """Delete an AI profile that is not selected."""
    cur = conn.execute("DELETE FROM ai_profiles WHERE uid = ?", (uid,))
    conn.commit()
    return cur.rowcount > 0


def mark_ai_profile_selected(conn, uid):
    """Make one AI profile the active profile."""
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
    """Create a saved AI profile from config.yaml when needed."""
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


def alert_content_fingerprint(alert):
    """Hash stable alert content so an EVE restart cannot duplicate the record."""
    supplied = str(alert.get("event_fingerprint") or "").strip()
    if supplied:
        return supplied
    raw = alert.get("raw_json")
    try:
        payload = json.loads(raw) if isinstance(raw, str) else raw
    except (TypeError, ValueError):
        payload = None
    if not isinstance(payload, (dict, list)):
        fields = (
            "suricata_event_id",
            "timestamp",
            "src_ip",
            "dest_ip",
            "src_port",
            "dest_port",
            "protocol",
            "signature",
            "category",
            "severity",
            "flow_id",
            "community_id",
        )
        payload = {field: alert.get(field) for field in fields}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def insert_alert(conn, alert):
    """Persist normalized and raw Suricata evidence under a stable event UID.

    Queryable endpoint/signature columns support case correlation and display.
    ``raw_json`` remains the authoritative original event. The canonical
    fingerprint makes replay idempotent, while the readable SUR UID gives the
    analyst a durable reference independent of a timestamp alone.
    """
    fingerprint = alert_content_fingerprint(alert)
    cur = conn.cursor()
    cur.execute(
        """
        INSERT OR IGNORE INTO alerts (
          event_fingerprint, suricata_event_id, timestamp, src_ip, dest_ip, src_port, dest_port,
          protocol, signature, category, severity, priority, flow_id, community_id, raw_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            fingerprint,
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
            alert.get("raw_json"),
        ),
    )
    if cur.rowcount == 0:
        row = conn.execute(
            "SELECT id, event_uid FROM alerts WHERE event_fingerprint = ?",
            (fingerprint,),
        ).fetchone()
        if not row:
            raise sqlite3.IntegrityError("Suricata alert insert was ignored without a matching fingerprint")
        alert["event_fingerprint"] = fingerprint
        alert["event_uid"] = row["event_uid"]
        alert["_duplicate"] = True
        return row["id"]
    alert_id = cur.lastrowid
    event_uid = alert.get("event_uid") or stable_record_uid("SUR", alert_id, alert.get("timestamp"))
    cur.execute("UPDATE alerts SET event_uid = ? WHERE id = ?", (event_uid, alert_id))
    alert["event_fingerprint"] = fingerprint
    alert["event_uid"] = event_uid
    alert["_duplicate"] = False
    conn.commit()
    return alert_id


def insert_detection(conn, detection):
    """Persist a unified case shell and assign its stable CASE UID.

    A detection is not another sensor alert. It is the parent record that
    carries the correlation window, representative endpoints, sensor state,
    and lifecycle status for one or many linked findings.
    """
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO detections (
          first_alert_id, first_seen, last_seen, src_ip, dest_ip, src_port, dest_port,
          protocol, community_id, sensor_state, agreement_state, correlation_method,
          correlation_confidence, detection_type,
          alert_count, unique_dest_ports, unique_dest_hosts, time_window_seconds,
          status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
    """Store the normalized model explanation used by the current case view.

    Structured columns make summary, confidence, recommendations, and evidence
    acknowledgement easy to display. The exact prompt and raw request proof go
    to ``ai_run_audits``; historical opinions go to ``ai_assessments``.
    """
    def sqlite_value(value):
        """Convert a Python value into a representation SQLite can store safely."""
        if isinstance(value, (dict, list)):
            return json.dumps(value, sort_keys=True)
        return value

    def sqlite_int(value, default=0):
        """Convert a nullable value into a SQLite-compatible integer."""
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    cur = conn.execute(
        """
        INSERT INTO ai_reports (
          detection_id, ai_profile_uid, model_provider, model_name, model_identity,
          model_endpoint, model_run_id, prompt_version, classification, confidence,
          reason, recommended_action, summary,
          who_summary, what_summary, when_summary, where_summary,
          why_summary, how_summary, next_steps_json, threat_intel_analysis_json,
          evidence_review_json, raw_response, elapsed_ms, prompt_sha256, prompt_chars
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
            sqlite_value(report.get("evidence_review") or {}),
            sqlite_value(report.get("raw_response")),
            sqlite_int(report.get("elapsed_ms", 0)),
            sqlite_value(report.get("prompt_sha256")),
            sqlite_int(report.get("prompt_chars", 0)),
        ),
    )
    conn.commit()
    return cur.lastrowid


def upsert_ai_run_audit(conn, detection_id, report, ai_report_id=None, assessment_type="initial"):
    """Persist authoritative request/response proof captured by Python.

    The exact prompt, normalized package, hashes, source map, omissions, safe
    request options, measured model metrics, and raw response are stored here.
    Credentials are removed before these values reach this function.
    """
    def encoded(value, fallback):
        """Encode one CSV field without allowing spreadsheet formula execution."""
        return json.dumps(value if value is not None else fallback, sort_keys=True)

    prompt = str(report.get("audit_prompt_text") or "")
    evidence = report.get("audit_evidence_package") or {}
    evidence_text = json.dumps(evidence, sort_keys=True, separators=(",", ":"))
    model_run = report.get("model_run_id")
    if not model_run or not prompt:
        return None
    status = report.get("audit_status") or "prepared"
    responded_at = utc_now() if status == "complete" else None
    conn.execute(
        """
        INSERT INTO ai_run_audits (
          detection_id, ai_report_id, assessment_type, model_run_id,
          ai_profile_uid, model_provider, model_name, model_endpoint, prompt_version,
          prompt_text, prompt_sha256, prompt_chars, prompt_bytes,
          evidence_package_json, evidence_sha256, evidence_chars, evidence_bytes,
          evidence_manifest_json, omission_manifest_json, source_map_json,
          request_options_json, response_metrics_json, response_text, response_sha256, response_chars,
          response_bytes, parse_status, parse_error, status, responded_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(detection_id, model_run_id) DO UPDATE SET
          ai_report_id = excluded.ai_report_id,
          assessment_type = excluded.assessment_type,
          response_text = excluded.response_text,
          response_sha256 = excluded.response_sha256,
          response_chars = excluded.response_chars,
          response_bytes = excluded.response_bytes,
          parse_status = excluded.parse_status,
          parse_error = excluded.parse_error,
          status = excluded.status,
          responded_at = excluded.responded_at
        """,
        (
            detection_id,
            ai_report_id,
            assessment_type,
            model_run,
            report.get("ai_profile_uid"),
            report.get("model_provider"),
            report.get("model_name"),
            report.get("model_endpoint"),
            report.get("prompt_version"),
            prompt,
            report.get("prompt_sha256") or hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
            int(report.get("prompt_chars") or len(prompt)),
            int(report.get("audit_prompt_bytes") or len(prompt.encode("utf-8"))),
            evidence_text,
            report.get("audit_evidence_sha256") or hashlib.sha256(evidence_text.encode("utf-8")).hexdigest(),
            int(report.get("audit_evidence_chars") or len(evidence_text)),
            int(report.get("audit_evidence_bytes") or len(evidence_text.encode("utf-8"))),
            encoded(report.get("audit_evidence_manifest"), {}),
            encoded(report.get("audit_omissions"), []),
            encoded(report.get("audit_source_map"), {}),
            encoded(report.get("audit_request_options"), {}),
            encoded(report.get("audit_response_metrics"), {}),
            report.get("raw_response"),
            report.get("audit_response_sha256"),
            report.get("audit_response_chars"),
            report.get("audit_response_bytes"),
            report.get("audit_parse_status"),
            report.get("audit_parse_error"),
            status,
            responded_at,
        ),
    )
    conn.commit()
    return conn.execute(
        "SELECT id FROM ai_run_audits WHERE detection_id = ? AND model_run_id = ?",
        (detection_id, model_run),
    ).fetchone()["id"]


def ai_run_audits_for_detection(conn, detection_id):
    """Load AI request audits for one detection."""
    rows = conn.execute(
        "SELECT * FROM ai_run_audits WHERE detection_id = ? ORDER BY id DESC",
        (detection_id,),
    ).fetchall()
    results = []
    json_fields = {
        "evidence_package_json": "evidence_package",
        "evidence_manifest_json": "evidence_manifest",
        "omission_manifest_json": "omission_manifest",
        "source_map_json": "source_map",
        "request_options_json": "request_options",
        "response_metrics_json": "response_metrics",
    }
    for row in rows:
        item = dict(row)
        for source, target in json_fields.items():
            raw = item.pop(source, None)
            try:
                item[target] = json.loads(raw or ("[]" if target == "omission_manifest" else "{}"))
            except (TypeError, json.JSONDecodeError):
                item[target] = [] if target == "omission_manifest" else {}
        item["model_response"] = {}
        item["model_evidence_review"] = {}
        if item.get("response_text"):
            try:
                from app.ai_client import normalize_report, parse_model_response

                normalized = normalize_report(parse_model_response(item["response_text"]))
                item["model_response"] = normalized
                item["model_evidence_review"] = normalized.get("evidence_review") or {}
            except (TypeError, ValueError):
                pass
        results.append(item)
    return results


def initial_ai_request_snapshot(conn, detection_id):
    """Return the exact audited input that produced the initial case summary."""
    row = conn.execute(
        """
        SELECT assessment_type, model_run_id, prompt_version, prompt_text,
               prompt_sha256, evidence_package_json, evidence_sha256,
               evidence_manifest_json, omission_manifest_json, source_map_json,
               request_options_json, prepared_at
        FROM ai_run_audits
        WHERE detection_id = ?
          AND assessment_type = 'initial'
          AND prompt_text <> ''
        ORDER BY id DESC
        LIMIT 1
        """,
        (detection_id,),
    ).fetchone()
    if not row:
        return None
    item = dict(row)
    for source, target, fallback in (
        ("evidence_package_json", "evidence_package", {}),
        ("evidence_manifest_json", "evidence_manifest", {}),
        ("omission_manifest_json", "omission_manifest", []),
        ("source_map_json", "source_map", {}),
        ("request_options_json", "request_options", {}),
    ):
        raw = item.pop(source, None)
        try:
            item[target] = json.loads(raw or json.dumps(fallback))
        except (TypeError, json.JSONDecodeError):
            item[target] = fallback
    return item


def insert_ai_assessment(conn, detection_id, report, assessment_type="initial", evidence_sources=None):
    """Append a historical opinion without replacing earlier model results.

    Initial analysis, reassessment, comparison, and experiment records may all
    discuss the same case. Append-only history makes those changes measurable
    instead of silently replacing the first response.
    """
    cur = conn.execute(
        """
        INSERT INTO ai_assessments (
          detection_id, assessment_type, provider,
          model_name, classification, confidence, reason,
          recommended_action, evidence_sources_json, response_time_ms,
          raw_response, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            detection_id,
            assessment_type,
            report.get("model_provider"),
            report.get("model_name") or "unknown",
            report.get("classification") or "Analyst Review Required",
            report.get("confidence") or "Low",
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


def insert_virustotal_verification(conn, detection_id, verification, ai_report_id=None, stage="initial"):
    """Save a VirusTotal verification result."""
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
    """Return all VirusTotal verification attempts stored for a detection."""
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


def insert_zeek_event(conn, event):
    """Persist one normalized Zeek row while retaining its original JSON text.

    Shared endpoint/UID/Community ID columns make correlation efficient across
    log types and sensors. Protocol-specific fields remain in ``raw_json`` and
    are selected later by ``zeek_evidence_details`` when a case needs context.
    """
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
    """Return the newest stored Zeek event ID."""
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
    """Find the Zeek flow with this UID."""
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
    """Link one authoritative sensor row to a unified detection exactly once.

    The unique sensor/event pair prevents one source event from being attached
    twice. ``raw_event`` is convenient lineage evidence, while the sensor name
    and record ID remain the canonical path back to ``alerts``/``zeek_events``.
    """
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
    """Return normalized Suricata and Zeek findings joined to a detection."""
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
          ,COALESCE(alerts.event_uid, zeek_events.event_uid) AS event_uid,
          alerts.raw_json AS alert_raw_json,
          zeek_events.raw_json AS zeek_raw_json,
          zeek_events.zeek_uid AS zeek_uid,
          zeek_events.log_type AS zeek_log_type
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
    findings = []
    for row in rows:
        item = dict(row)
        sensor = str(item.get("sensor") or "unknown").lower()
        source_table = "alerts" if sensor == "suricata" else "zeek_events"
        raw_text = item.pop("alert_raw_json", None) if sensor == "suricata" else item.pop("zeek_raw_json", None)
        item.pop("zeek_raw_json", None)
        item.pop("alert_raw_json", None)
        if raw_text is None:
            raw_text = item.get("raw_event")
        if isinstance(raw_text, (dict, list)):
            raw_record = raw_text
            canonical_raw = json.dumps(raw_text, sort_keys=True, separators=(",", ":"))
        else:
            canonical_raw = str(raw_text or "")
            try:
                raw_record = json.loads(canonical_raw) if canonical_raw else {}
            except (TypeError, json.JSONDecodeError):
                raw_record = {"unparsed": canonical_raw}
        item["source_table"] = source_table
        item["source_record_id"] = item.get("sensor_event_id")
        item["raw_record"] = raw_record
        item["raw_record_sha256"] = hashlib.sha256(canonical_raw.encode("utf-8")).hexdigest()
        item["raw_record_bytes"] = len(canonical_raw.encode("utf-8"))
        item["field_provenance"] = {
            "finding_name": f"sensor_findings.finding_name derived from {source_table}",
            "timestamp": f"{source_table}.timestamp",
            "source_ip": f"{source_table}.{'src_ip' if sensor == 'suricata' else 'source_ip'}",
            "source_port": f"{source_table}.{'src_port' if sensor == 'suricata' else 'source_port'}",
            "destination_ip": f"{source_table}.{'dest_ip' if sensor == 'suricata' else 'destination_ip'}",
            "destination_port": f"{source_table}.{'dest_port' if sensor == 'suricata' else 'destination_port'}",
            "protocol": f"{source_table}.protocol",
            "community_id": "sensor_findings.community_id with sensor record fallback",
        }
        findings.append(item)
    return findings


def sensor_finding_detection_id(conn, sensor, sensor_event_id):
    """Find the detection that already owns a sensor event identifier."""
    row = conn.execute(
        "SELECT detection_id FROM sensor_findings WHERE sensor = ? AND sensor_event_id = ?",
        (sensor, sensor_event_id),
    ).fetchone()
    return row["detection_id"] if row else None


def detection_by_id(conn, detection_id):
    """Load one detection by database ID with retired score fields removed."""
    row = conn.execute("SELECT * FROM detections WHERE id = ?", (detection_id,)).fetchone()
    return without_operational_scores(row) if row else None


def detection_by_case_uid(conn, case_uid):
    """Load one detection using its stable analyst-facing case UID."""
    row = conn.execute("SELECT * FROM detections WHERE case_uid = ?", (case_uid,)).fetchone()
    return without_operational_scores(row) if row else None


def _event_time(value):
    """Parse a stored sensor timestamp into a timezone-aware datetime."""
    if not value:
        return None
    text = str(value).replace("Z", "+00:00")
    if len(text) >= 5 and text[-5] in "+-" and text[-4:].isdigit():
        text = f"{text[:-2]}:{text[-2:]}"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _event_endpoints(event):
    """Extract normalized source and destination addresses and ports."""
    return (
        event.get("src_ip") or event.get("source_ip"),
        event.get("dest_ip") or event.get("destination_ip"),
        event.get("src_port") or event.get("source_port"),
        event.get("dest_port") or event.get("destination_port"),
    )


def _event_name(event):
    """Choose the most descriptive available name for a sensor event."""
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
    """Collect normalized addresses, domains, URLs, and hashes from an event."""
    observables = set()

    def collect(value, key=""):
        """Collect normalized observable values without duplicates."""
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
    """Build observable sets for candidate detections during correlation."""
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
    """Test whether two same-sensor events represent repeated behavior."""
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


DEFAULT_CORRELATION_STRENGTHS = {
    "community_id": 1.0,
    "community_id_same_sensor": 0.95,
    "zeek_uid": 0.95,
    "flow_time": 0.85,
    "shared_observable": 0.82,
    "same_sensor_behavior": 0.78,
}


def correlation_strength(name, configured=None):
    """Resolve a named correlation method to its configured confidence."""
    values = {**DEFAULT_CORRELATION_STRENGTHS, **(configured or {})}
    try:
        value = float(values.get(name, 0.0))
    except (TypeError, ValueError):
        value = DEFAULT_CORRELATION_STRENGTHS.get(name, 0.0)
    return max(0.0, min(1.0, value))


def find_correlated_detection(
    conn,
    event,
    sensor,
    tolerance_seconds=10,
    same_sensor_window_seconds=300,
    strengths=None,
):
    """Find the strongest existing case compatible with an incoming finding.

    Matching is attempted from strongest to weakest: Community ID, Zeek UID,
    endpoint/time flow, shared observables, then repeated same-sensor behavior.
    The returned strength is a configured rule value, not a probability.
    """
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
            return dict(row), "community_id", correlation_strength("community_id", strengths)

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
            return dict(row), "community_id_same_sensor", correlation_strength("community_id_same_sensor", strengths)

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
            return dict(row), "zeek_uid", correlation_strength("zeek_uid", strengths)

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
        return candidate, "flow_time", correlation_strength("flow_time", strengths)

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
                return candidate, "shared_observable", correlation_strength("shared_observable", strengths)

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
            return candidate, "same_sensor_behavior", correlation_strength("same_sensor_behavior", strengths)
    return None, "none", 0.0


def fuse_detection(conn, detection_id, event, correlation_method, correlation_confidence):
    """Recalculate case bounds and sensor state after adding a new finding."""
    detection = detection_by_id(conn, detection_id)
    if not detection:
        return None
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
            correlation_confidence = ?,
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
    """Load the saved read position for a Zeek log."""
    row = conn.execute(
        "SELECT log_type, path, inode, offset, updated_at FROM zeek_ingest_checkpoints WHERE log_type = ?",
        (log_type,),
    ).fetchone()
    return dict(row) if row else None


def get_suricata_checkpoint(conn, source="eve"):
    """Return the stored suricata checkpoint value when available."""
    row = conn.execute(
        """
        SELECT source, path, inode, offset, updated_at
        FROM suricata_ingest_checkpoints
        WHERE source = ?
        """,
        (source,),
    ).fetchone()
    return dict(row) if row else None


def upsert_suricata_checkpoint(conn, path, inode, offset, source="eve"):
    """Add or update a suricata checkpoint record."""
    conn.execute(
        """
        INSERT INTO suricata_ingest_checkpoints (
          source, path, inode, offset, updated_at
        )
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(source) DO UPDATE SET
          path = excluded.path,
          inode = excluded.inode,
          offset = excluded.offset,
          updated_at = excluded.updated_at
        """,
        (source, str(path), int(inode or 0), int(offset or 0), utc_now()),
    )
    conn.commit()


def upsert_zeek_checkpoint(conn, log_type, path, inode, offset):
    """Save the current read position for a Zeek log."""
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
    """Return the newest Zeek log entries."""
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
    """Count stored Zeek events by log type."""
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
    """Load the raw Zeek record for one event."""
    try:
        return json.loads(row["raw_json"] or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}


def _counter_rows(counter, name, limit=8):
    """Convert a Counter into dashboard rows sorted by frequency."""
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
    """Select and summarize Zeek rows related to a unified detection.

    Community ID and directly linked Zeek UIDs are preferred. Endpoint/time
    matches and repeated-source context provide fallbacks. The returned summary
    exposes bytes, duration, DNS/TLS/HTTP metadata, and timing regularity without
    claiming access to encrypted payload contents.
    """
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
    parsed_start = _event_time(start_text)
    parsed_end = _event_time(end_text)
    if parsed_start and parsed_end:
        window_start = min(parsed_start, parsed_end) - timedelta(seconds=seconds)
        window_end = max(parsed_start, parsed_end) + timedelta(seconds=seconds)
        start_value = window_start.isoformat()
        end_value = window_end.isoformat()
    else:
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
        item["details"] = zeek_evidence_details(raw, log_type)
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


def insert_response(conn, response):
    """Persist a new response record in SQLite."""
    cur = conn.execute(
        """
        INSERT INTO responses (
          detection_id, final_classification, final_action,
          target_ip, response_method, response_status, response_time_ms
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            response.get("detection_id"),
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


def upsert_pending_review(conn, response, review_days=3):
    """Add a case to the analyst queue or update its deadline."""
    if response.get("final_action") != "human_review":
        return

    now = datetime.now(timezone.utc)
    due_at = now + timedelta(days=review_days)
    values = (
        response.get("detection_id"),
        response.get("final_classification"),
        response.get("final_action"),
        due_at.isoformat(),
    )
    if "original_score" in table_columns(conn, "analyst_reviews"):
        conn.execute(
            """
            INSERT OR IGNORE INTO analyst_reviews (
              detection_id, original_score, original_classification, original_action, due_at
            )
            VALUES (?, 0, ?, ?, ?)
            """,
            values,
        )
    else:
        conn.execute(
            """
            INSERT OR IGNORE INTO analyst_reviews (
              detection_id, original_classification, original_action, due_at
            )
            VALUES (?, ?, ?, ?)
            """,
            values,
        )
    conn.commit()


def insert_app_event(conn, level, component, message, details=None):
    """Persist a new app event record in SQLite."""
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
    """Delete operational case history while preserving configuration tables."""
    tables = [
        "ai_comparison_review_history",
        "ai_comparison_votes",
        "ai_comparison_candidates",
        "ai_comparison_runs",
        "ai_run_audits",
        "ai_reports",
        "responses",
        "analyst_reviews",
        "tuning_labels",
        "threat_intel_usage",
        "ai_assessments",
        "sensor_findings",
        "virustotal_verifications",
        "threat_intel_lookups",
        "detections",
        "alerts",
        "zeek_ingest_checkpoints",
        "zeek_events",
        "app_events",
    ]
    counts = {}
    for table in tables:
        if not table_exists(conn, table):
            continue
        counts[table] = conn.execute(f"SELECT COUNT(*) AS count FROM {table}").fetchone()["count"]
        conn.execute(f"DELETE FROM {table}")
    conn.commit()
    return counts


def latest_sensor_alerts(conn, limit=50, sensor_filter=None):
    """Return recent cases with their Suricata and Zeek findings."""
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
        item = without_operational_scores(row)
        item["sensor_findings"] = sensor_findings_for_detection(conn, item["detection_id"])
        results.append(item)
    return results


def ai_model_comparison(conn):
    """Summarize saved results by AI model."""
    rows = conn.execute(
        """
        SELECT
          COALESCE(model_identity, 'unknown model') AS model_identity,
          COALESCE(ai_profile_uid, 'legacy-profile') AS ai_profile_uid,
          COALESCE(model_provider, 'unknown') AS model_provider,
          COALESCE(model_name, 'unknown') AS model_name,
          COALESCE(classification, 'No opinion') AS classification,
          COUNT(*) AS count,
          AVG(COALESCE(elapsed_ms, 0)) AS avg_elapsed_ms
        FROM ai_reports
        GROUP BY ai_profile_uid, model_identity, classification
        ORDER BY ai_profile_uid ASC, count DESC
        """
    ).fetchall()
    return [dict(row) for row in rows]


def ip_enrichment_profile(ip_address):
    """Classify an address and state whether external enrichment is allowed."""
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
    """Return the latest cached intelligence for one IP address."""
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
    """Add or update a threat intel lookup record."""
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
    """Record threat intel usage for audit and later review."""
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
    """Summarize how threat-intelligence sources were used."""
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
        item = without_operational_scores(row)
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
    """Replace all stored threat intel indicators in one safe database update."""
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
    """Update a stored threat intel source."""
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
    """Load threat-intelligence source records for one detection."""
    rows = conn.execute("SELECT * FROM threat_intel_sources ORDER BY source").fetchall()
    return {row["source"]: dict(row) for row in rows}


def threat_intel_matches(conn, indicator, indicator_type="ip"):
    """Load threat-intelligence matches for one detection."""
    value = str(indicator or "").strip()
    if not value:
        return []
    rows = conn.execute(
        """
        SELECT id AS source_record_id, indicator, indicator_type, source, category, malware_family,
               confidence, first_seen, last_seen, expires_at, source_reference,
               imported_at
        FROM threat_intel_indicators
        WHERE lower(indicator) = lower(?)
        ORDER BY confidence DESC, source
        """,
        (value,),
    ).fetchall()
    matches = [{**dict(row), "source_table": "threat_intel_indicators"} for row in rows]
    if indicator_type == "ip":
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            address = None
        if address:
            cidr_rows = conn.execute(
                """
                SELECT id AS source_record_id, indicator, indicator_type, source, category, malware_family,
                       confidence, first_seen, last_seen, expires_at, source_reference,
                       imported_at
                FROM threat_intel_indicators
                WHERE indicator_type = 'cidr'
                """
            ).fetchall()
            for row in cidr_rows:
                try:
                    if address in ipaddress.ip_network(row["indicator"], strict=False):
                        matches.append({**dict(row), "source_table": "threat_intel_indicators"})
                except ValueError:
                    continue
    return matches


def threat_intel_provider_results(conn, indicator, providers, indicator_type="ip"):
    """Load each provider's result for one detection."""
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
    """Select frequently observed public addresses eligible for enrichment."""
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


def detection_time_window(conn, detection_type=None):
    """Return the first and last timestamps for matching detections."""
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
    """Return recent cases with the evidence behind each decision."""
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
            (
              lower(COALESCE(responses.final_classification, '')) LIKE '%human%'
              OR lower(COALESCE(responses.final_classification, '')) LIKE '%analyst%'
            )
            """
        )
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
        item = without_operational_scores(row)
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
    """Assemble all stored evidence needed by the legacy investigation API."""
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
          ai_reports.evidence_review_json AS ai_evidence_review_json,
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
          responses.final_classification,
          responses.final_action,
          responses.target_ip,
          responses.response_status,
          responses.response_time_ms,
          responses.created_at AS response_created_at,
          analyst_reviews.review_status,
          analyst_reviews.analyst_name,
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

    item = without_operational_scores(row)
    # A detection is visible before the asynchronous AI worker reaches it.
    # Expose that distinction so the dashboard does not manufacture model
    # identity, recommendations, or classifications for an unassessed case.
    item["ai_report_available"] = bool(item.get("ai_created_at"))
    item["decision_available"] = bool(item.get("response_created_at"))
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
    raw_evidence_review = item.pop("ai_evidence_review_json", None)
    try:
        item["ai_evidence_review"] = json.loads(raw_evidence_review or "{}")
    except (TypeError, json.JSONDecodeError):
        item["ai_evidence_review"] = {}
    item["src_ip_profile"] = ip_enrichment_profile(item.get("src_ip"))
    item["dest_ip_profile"] = ip_enrichment_profile(item.get("dest_ip"))
    item["src_otx"] = latest_threat_intel_for_ip(conn, item.get("src_ip"), "otx")
    item["dest_otx"] = latest_threat_intel_for_ip(conn, item.get("dest_ip"), "otx")
    item["sensor_findings"] = sensor_findings_for_detection(conn, detection_id)
    item["selected_ai_explanation"] = selected_case_explanation(conn, detection_id)
    item["ai_run_audits"] = ai_run_audits_for_detection(conn, detection_id)
    item["virustotal_verifications"] = virustotal_verifications_for_detection(conn, detection_id)
    item["ai_assessments"] = [
        without_operational_scores(value)
        for value in conn.execute(
            "SELECT * FROM ai_assessments WHERE detection_id = ? ORDER BY id",
            (detection_id,),
        ).fetchall()
    ]
    item["responses"] = [
        without_operational_scores(value)
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
    """Assemble the complete case, evidence, AI, and review workspace."""
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


def latest_app_events(conn, limit=100):
    """Return recent application log messages."""
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
    """Mark overdue analyst reviews as expired."""
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
    """Add older review-required AI reports to the analyst queue."""
    legacy_score = "original_score," if "original_score" in table_columns(
        conn, "analyst_reviews"
    ) else ""
    legacy_value = "0," if legacy_score else ""
    conn.execute(
        f"""
        INSERT OR IGNORE INTO analyst_reviews (
          detection_id,
          {legacy_score}
          original_classification,
          original_action,
          due_at,
          created_at
        )
        SELECT
          responses.detection_id,
          {legacy_value}
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
    """List stored review queue."""
    seed_pending_reviews_from_responses(conn)
    expire_stale_reviews(conn)
    rows = conn.execute(
        """
        SELECT
          analyst_reviews.id,
          analyst_reviews.detection_id,
          analyst_reviews.original_classification,
          analyst_reviews.original_action,
          analyst_reviews.review_status,
          analyst_reviews.analyst_name,
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
    return [without_operational_scores(row) for row in rows]


def submit_analyst_review(
    conn,
    detection_id,
    action,
    analyst_name,
    notes="",
    classification=None,
    tuning_label=None,
):
    """Store an analyst decision and apply its final case classification."""
    now = datetime.now(timezone.utc).isoformat()
    existing = conn.execute(
        "SELECT id, original_classification, original_action FROM analyst_reviews WHERE detection_id = ?",
        (detection_id,),
    ).fetchone()
    if not existing:
        source = conn.execute(
            """
            SELECT
              responses.final_classification,
              responses.final_action
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
        original_classification = source["final_classification"] or "Analyst Review Required"
        original_action = source["final_action"] or "human_review"
        values = (
            detection_id,
            original_classification,
            original_action,
            (datetime.now(timezone.utc) + timedelta(days=3)).isoformat(),
        )
        if "original_score" in table_columns(conn, "analyst_reviews"):
            conn.execute(
                """
                INSERT INTO analyst_reviews (
                  detection_id, original_score, original_classification, original_action, due_at
                )
                VALUES (?, 0, ?, ?, ?)
                """,
                values,
            )
        else:
            conn.execute(
                """
                INSERT INTO analyst_reviews (
                  detection_id, original_classification, original_action, due_at
                )
                VALUES (?, ?, ?, ?)
                """,
                values,
            )
        existing = {
            "original_classification": original_classification,
            "original_action": original_action,
        }

    if action == "confirm":
        review_status = "confirmed"
        analyst_classification = existing["original_classification"]
        analyst_action = existing["original_action"]
    else:
        review_status = "overridden"
        analyst_classification = classification
        analyst_action = action

    conn.execute(
        """
        UPDATE analyst_reviews
        SET review_status = ?,
            analyst_name = ?,
            analyst_classification = ?,
            analyst_action = ?,
            analyst_notes = ?,
            reviewed_at = ?
        WHERE detection_id = ?
        """,
        (
            review_status,
            analyst_name,
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


def detections_without_ai_reports(
    conn,
    limit=50,
    model_identity=None,
    ai_profile_uid=None,
    newest_first=False,
    minimum_age_seconds=0,
):
    """Return durable cases for which the selected model has no AI report.

    No placeholder row is inserted into ``ai_reports`` when a case is created.
    Instead, this LEFT JOIN finds a detection whose matching report is absent.
    Ordering by detection ID provides a stable oldest-first queue by default;
    once the worker stores a report, the next query naturally excludes it. A
    Zeek-only case can have no ``alerts`` row, hence the COALESCE fallbacks to
    case fields and its first linked sensor finding.
    """
    join_filters = []
    params = []
    if ai_profile_uid:
        join_filters.append("AND ai_reports.ai_profile_uid = ?")
        params.append(ai_profile_uid)
    elif model_identity:
        join_filters.append("AND ai_reports.model_identity = ?")
        params.append(model_identity)
    join_filter = " ".join(join_filters)
    age_filter = ""
    if minimum_age_seconds:
        age_filter = "AND detections.created_at <= datetime('now', ?)"
        params.append(f"-{max(0, int(minimum_age_seconds))} seconds")
    order_direction = "DESC" if newest_first else "ASC"
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
          AND NOT EXISTS (
            SELECT 1 FROM ai_cancelled_detections
            WHERE ai_cancelled_detections.detection_id = detections.id
          )
          {age_filter}
        ORDER BY
          CASE WHEN detections.sensor_state = 'multi_sensor' THEN 0 ELSE 1 END,
          detections.id {order_direction}
        LIMIT ?
        """,
        params,
    ).fetchall()
    return [dict(row) for row in rows]


def _evaluation_bool(value):
    """Convert a saved value to True, False, or None."""
    if value is None:
        return None
    return bool(value)


def _evaluation_scenario_row(row):
    """Convert one SQLite scenario row into an API dictionary."""
    if not row:
        return None
    item = dict(row)
    item["authorized_activity"] = _evaluation_bool(item.get("authorized_activity"))
    item["attack_succeeded"] = _evaluation_bool(item.get("attack_succeeded"))
    try:
        item["expected_sensors"] = json.loads(item.get("expected_sensors") or "[]")
    except (TypeError, json.JSONDecodeError):
        item["expected_sensors"] = []
    try:
        item["candidate_scope"] = json.loads(
            item.pop("candidate_scope_json", None) or "{}"
        )
    except (TypeError, json.JSONDecodeError):
        item["candidate_scope"] = {}
    item["candidate_scope"].setdefault(
        "time_window",
        {"start": item.get("start_time"), "end": item.get("end_time")},
    )
    item["candidate_scope"].setdefault(
        "source_ips", [item["source_ip"]] if item.get("source_ip") else []
    )
    item["candidate_scope"].setdefault(
        "destination_ips",
        [item["destination_ip"]] if item.get("destination_ip") else [],
    )
    item["candidate_scope"].setdefault("include_linked_case_events", True)
    item["candidate_scope"].setdefault("manual_distractor_event_uids", [])
    return item


def create_evaluation_scenario(conn, scenario):
    """Create and persist a new evaluation scenario."""
    now = utc_now()
    conn.execute(
        """
        INSERT INTO evaluation_scenarios (
          scenario_uid, name, experiment_type, ground_truth_class,
          authorized_activity, attack_succeeded, source_ip, destination_ip,
          start_time, end_time, expected_case_count,
          expected_min_classification, expected_max_classification,
          expected_sensors, candidate_scope_json, notes, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scenario["scenario_uid"],
            scenario["name"],
            scenario["experiment_type"],
            scenario["ground_truth_class"],
            scenario.get("authorized_activity"),
            scenario.get("attack_succeeded"),
            scenario.get("source_ip"),
            scenario.get("destination_ip"),
            scenario["start_time"],
            scenario["end_time"],
            int(scenario.get("expected_case_count", 1)),
            scenario.get("expected_min_classification"),
            scenario.get("expected_max_classification"),
            json.dumps(scenario.get("expected_sensors") or []),
            json.dumps(scenario.get("candidate_scope") or {}, sort_keys=True),
            scenario.get("notes"),
            now,
            now,
        ),
    )
    conn.commit()
    return get_evaluation_scenario(conn, scenario["scenario_uid"])


def update_evaluation_scenario(conn, scenario_uid, scenario):
    """Update a stored evaluation scenario."""
    now = utc_now()
    cur = conn.execute(
        """
        UPDATE evaluation_scenarios
        SET name = ?, experiment_type = ?, ground_truth_class = ?,
            authorized_activity = ?, attack_succeeded = ?,
            source_ip = ?, destination_ip = ?, start_time = ?, end_time = ?,
            expected_case_count = ?, expected_min_classification = ?,
            expected_max_classification = ?, expected_sensors = ?,
            candidate_scope_json = ?, notes = ?, updated_at = ?
        WHERE scenario_uid = ?
        """,
        (
            scenario["name"],
            scenario["experiment_type"],
            scenario["ground_truth_class"],
            scenario.get("authorized_activity"),
            scenario.get("attack_succeeded"),
            scenario.get("source_ip"),
            scenario.get("destination_ip"),
            scenario["start_time"],
            scenario["end_time"],
            int(scenario.get("expected_case_count", 1)),
            scenario.get("expected_min_classification"),
            scenario.get("expected_max_classification"),
            json.dumps(scenario.get("expected_sensors") or []),
            json.dumps(scenario.get("candidate_scope") or {}, sort_keys=True),
            scenario.get("notes"),
            now,
            scenario_uid,
        ),
    )
    conn.commit()
    return get_evaluation_scenario(conn, scenario_uid) if cur.rowcount else None


def list_evaluation_scenarios(conn, limit=200, experiment_type=None):
    """List stored evaluation scenarios."""
    where = ""
    params = []
    if experiment_type:
        where = "WHERE experiment_type = ?"
        params.append(experiment_type)
    params.append(int(limit))
    rows = conn.execute(
        f"""
        SELECT scenarios.*,
               COUNT(DISTINCT links.case_uid) AS linked_case_count,
               COUNT(DISTINCT labels.event_sensor || ':' || labels.event_uid) AS event_label_count
        FROM evaluation_scenarios AS scenarios
        LEFT JOIN evaluation_case_links AS links
          ON links.scenario_uid = scenarios.scenario_uid
        LEFT JOIN evaluation_event_labels AS labels
          ON labels.scenario_uid = scenarios.scenario_uid
        {where}
        GROUP BY scenarios.scenario_uid
        ORDER BY scenarios.start_time DESC, scenarios.scenario_uid
        LIMIT ?
        """,
        params,
    ).fetchall()
    return [_evaluation_scenario_row(row) for row in rows]


def get_evaluation_scenario(conn, scenario_uid):
    """Return the stored evaluation scenario value when available."""
    row = conn.execute(
        "SELECT * FROM evaluation_scenarios WHERE scenario_uid = ?",
        (scenario_uid,),
    ).fetchone()
    item = _evaluation_scenario_row(row)
    if not item:
        return None
    item["case_links"] = list_evaluation_case_links(conn, scenario_uid)
    item["event_labels"] = list_evaluation_event_labels(conn, scenario_uid)
    return item


def delete_evaluation_scenario(conn, scenario_uid):
    """Delete a stored evaluation scenario."""
    if not conn.execute(
        "SELECT 1 FROM evaluation_scenarios WHERE scenario_uid = ?",
        (scenario_uid,),
    ).fetchone():
        return False
    for table in (
        "evaluation_case_links",
        "evaluation_event_labels",
    ):
        conn.execute(f"DELETE FROM {table} WHERE scenario_uid = ?", (scenario_uid,))
    conn.execute(
        "DELETE FROM evaluation_scenarios WHERE scenario_uid = ?",
        (scenario_uid,),
    )
    conn.commit()
    return True


def upsert_evaluation_case_link(conn, scenario_uid, link):
    """Add or update a evaluation case link record."""
    now = utc_now()
    conn.execute(
        """
        INSERT INTO evaluation_case_links (
          scenario_uid, case_uid, relationship_status, analyst_confirmed,
          notes, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(scenario_uid, case_uid) DO UPDATE SET
          relationship_status = excluded.relationship_status,
          analyst_confirmed = excluded.analyst_confirmed,
          notes = excluded.notes,
          updated_at = excluded.updated_at
        """,
        (
            scenario_uid,
            link["case_uid"],
            link.get("relationship_status", "expected_related"),
            int(bool(link.get("analyst_confirmed"))),
            link.get("notes"),
            now,
            now,
        ),
    )
    conn.commit()
    return next(
        (
            item
            for item in list_evaluation_case_links(conn, scenario_uid)
            if item["case_uid"] == link["case_uid"]
        ),
        None,
    )


def list_evaluation_case_links(conn, scenario_uid):
    """List stored evaluation case links."""
    rows = conn.execute(
        """
        SELECT links.*, detections.id AS detection_id, detections.first_seen,
               detections.last_seen, detections.detection_type,
               detections.sensor_state, responses.final_classification
        FROM evaluation_case_links AS links
        LEFT JOIN detections ON detections.case_uid = links.case_uid
        LEFT JOIN responses ON responses.id = (
          SELECT MAX(response_rows.id)
          FROM responses AS response_rows
          WHERE response_rows.detection_id = detections.id
        )
        WHERE links.scenario_uid = ?
        ORDER BY links.created_at, links.case_uid
        """,
        (scenario_uid,),
    ).fetchall()
    items = []
    for row in rows:
        item = dict(row)
        item["analyst_confirmed"] = bool(item.get("analyst_confirmed"))
        item["case_exists"] = item.get("detection_id") is not None
        items.append(item)
    return items


def delete_evaluation_case_link(conn, scenario_uid, case_uid):
    """Delete a stored evaluation case link."""
    cur = conn.execute(
        "DELETE FROM evaluation_case_links WHERE scenario_uid = ? AND case_uid = ?",
        (scenario_uid, case_uid),
    )
    conn.commit()
    return cur.rowcount > 0


def upsert_evaluation_event_label(conn, scenario_uid, label):
    """Add or update a evaluation event label record."""
    now = utc_now()
    conn.execute(
        """
        INSERT INTO evaluation_event_labels (
          scenario_uid, event_uid, event_sensor, expected_case_uid, actual_case_uid,
          expected_membership, actual_membership, label, notes,
          created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(scenario_uid, event_sensor, event_uid) DO UPDATE SET
          expected_case_uid = excluded.expected_case_uid,
          actual_case_uid = excluded.actual_case_uid,
          expected_membership = excluded.expected_membership,
          actual_membership = excluded.actual_membership,
          label = excluded.label,
          notes = excluded.notes,
          updated_at = excluded.updated_at
        """,
        (
            scenario_uid,
            label["event_uid"],
            label["event_sensor"],
            label.get("expected_case_uid"),
            label.get("actual_case_uid"),
            int(bool(label.get("expected_membership"))),
            int(bool(label.get("actual_membership"))),
            label["label"],
            label.get("notes"),
            now,
            now,
        ),
    )
    conn.commit()
    return next(
        (
            item
            for item in list_evaluation_event_labels(conn, scenario_uid)
            if item["event_uid"] == label["event_uid"]
            and item["event_sensor"] == label["event_sensor"]
        ),
        None,
    )


def list_evaluation_event_labels(conn, scenario_uid):
    """List stored evaluation event labels."""
    rows = conn.execute(
        """
        SELECT * FROM evaluation_event_labels
        WHERE scenario_uid = ?
        ORDER BY event_sensor, event_uid
        """,
        (scenario_uid,),
    ).fetchall()
    items = []
    for row in rows:
        item = dict(row)
        item["expected_membership"] = bool(item.get("expected_membership"))
        item["actual_membership"] = bool(item.get("actual_membership"))
        items.append(item)
    return items


def evaluation_candidate_events(conn, scenario_uid, limit=5000):
    """Find sensor events that may belong to an evaluation scenario."""
    scenario = get_evaluation_scenario(conn, scenario_uid)
    if not scenario:
        return []
    scope = scenario.get("candidate_scope") or {}
    start = _event_time((scope.get("time_window") or {}).get("start"))
    end = _event_time((scope.get("time_window") or {}).get("end"))
    if not start or not end:
        return []
    scope_ips = {
        str(value)
        for value in (
            list(scope.get("source_ips") or [])
            + list(scope.get("destination_ips") or [])
        )
        if value
    }
    distractors = {
        str(value)
        for value in (scope.get("manual_distractor_event_uids") or [])
        if value
    }
    linked_cases = {
        link["case_uid"] for link in (scenario.get("case_links") or [])
    }
    linked_event_keys = set()
    if scope.get("include_linked_case_events", True) and linked_cases:
        placeholders = ",".join("?" for _ in linked_cases)
        rows = conn.execute(
            f"""
            SELECT findings.sensor, findings.sensor_event_id
            FROM sensor_findings AS findings
            JOIN detections ON detections.id = findings.detection_id
            WHERE detections.case_uid IN ({placeholders})
            """,
            tuple(linked_cases),
        ).fetchall()
        linked_event_keys = {
            (row["sensor"], int(row["sensor_event_id"])) for row in rows
        }

    rows = conn.execute(
        """
        SELECT 'suricata' AS sensor, alerts.id AS sensor_event_id,
               alerts.event_uid, alerts.timestamp,
               alerts.src_ip AS source_ip, alerts.src_port AS source_port,
               alerts.dest_ip AS destination_ip, alerts.dest_port AS destination_port,
               alerts.protocol, alerts.community_id, alerts.flow_id AS sensor_uid,
               alerts.signature AS event_name,
               detections.case_uid AS actual_case_uid
        FROM alerts
        LEFT JOIN sensor_findings
          ON sensor_findings.sensor = 'suricata'
         AND sensor_findings.sensor_event_id = alerts.id
        LEFT JOIN detections ON detections.id = sensor_findings.detection_id
        WHERE alerts.event_uid IS NOT NULL
        UNION ALL
        SELECT 'zeek' AS sensor, zeek_events.id AS sensor_event_id,
               zeek_events.event_uid, zeek_events.timestamp,
               zeek_events.source_ip, zeek_events.source_port,
               zeek_events.destination_ip, zeek_events.destination_port,
               zeek_events.protocol, zeek_events.community_id,
               zeek_events.zeek_uid AS sensor_uid,
               COALESCE(zeek_events.event_name, zeek_events.message) AS event_name,
               detections.case_uid AS actual_case_uid
        FROM zeek_events
        LEFT JOIN sensor_findings
          ON sensor_findings.sensor = 'zeek'
         AND sensor_findings.sensor_event_id = zeek_events.id
        LEFT JOIN detections ON detections.id = sensor_findings.detection_id
        WHERE zeek_events.event_uid IS NOT NULL
        """
    ).fetchall()
    within_window = []
    for row in rows:
        item = dict(row)
        timestamp = _event_time(item.get("timestamp"))
        if not timestamp or timestamp < start or timestamp > end:
            continue
        item["_direct_scope_match"] = bool(
            {item.get("source_ip"), item.get("destination_ip")} & scope_ips
        )
        item["_linked_case_match"] = (
            item["sensor"], int(item["sensor_event_id"])
        ) in linked_event_keys
        item["_manual_distractor"] = item.get("event_uid") in distractors
        within_window.append(item)

    anchor_community_ids = {
        item["community_id"]
        for item in within_window
        if item.get("community_id")
        and (item["_direct_scope_match"] or item["_linked_case_match"])
    }
    anchor_zeek_uids = {
        item["sensor_uid"]
        for item in within_window
        if item["sensor"] == "zeek"
        and item.get("sensor_uid")
        and (item["_direct_scope_match"] or item["_linked_case_match"])
    }
    candidates = []
    seen = set()
    for item in within_window:
        reasons = []
        if item["_direct_scope_match"]:
            reasons.append("scenario_endpoint")
        if item["_linked_case_match"]:
            reasons.append("linked_case")
        if item["_manual_distractor"]:
            reasons.append("manual_distractor")
        if item.get("community_id") in anchor_community_ids:
            reasons.append("shared_community_id")
        if (
            item["sensor"] == "zeek"
            and item.get("sensor_uid") in anchor_zeek_uids
        ):
            reasons.append("shared_zeek_uid")
        if not reasons:
            continue
        key = (item["sensor"], item["event_uid"])
        if key in seen:
            continue
        seen.add(key)
        item.pop("_direct_scope_match", None)
        item.pop("_linked_case_match", None)
        item.pop("_manual_distractor", None)
        item["candidate_reasons"] = list(dict.fromkeys(reasons))
        candidates.append(item)
    candidates.sort(
        key=lambda item: (
            _event_time(item.get("timestamp")) or datetime.min.replace(tzinfo=timezone.utc),
            item["sensor"],
            item["event_uid"],
        )
    )
    return candidates[: max(1, min(int(limit), 10000))]


def evaluation_correlation_metrics(conn, scenario_uid):
    """Calculate case-correlation results for one scenario."""
    if not get_evaluation_scenario(conn, scenario_uid):
        return None
    candidates = evaluation_candidate_events(conn, scenario_uid)
    candidate_keys = {
        (item["sensor"], item["event_uid"]) for item in candidates
    }
    all_labels = list_evaluation_event_labels(conn, scenario_uid)
    labels = [
        item
        for item in all_labels
        if (item["event_sensor"], item["event_uid"]) in candidate_keys
    ]
    out_of_scope_labels = len(all_labels) - len(labels)
    true_positives = 0
    false_positives = 0
    false_negatives = 0
    true_negatives = 0
    wrong_case_assignments = 0
    incomplete_labels = 0
    for item in labels:
        expected = item.get("expected_case_uid")
        actual = item.get("actual_case_uid")
        if expected and actual:
            if expected == actual:
                true_positives += 1
            else:
                false_negatives += 1
                false_positives += 1
                wrong_case_assignments += 1
        elif expected:
            false_negatives += 1
        elif actual:
            false_positives += 1
        elif item.get("expected_membership") or item.get("actual_membership"):
            incomplete_labels += 1
        else:
            true_negatives += 1

    def divided(numerator, denominator):
        """Return a safe division result while avoiding division by zero."""
        return round(numerator / denominator, 4) if denominator else None

    precision = divided(true_positives, true_positives + false_positives)
    recall = divided(true_positives, true_positives + false_negatives)
    f1 = (
        round((2 * precision * recall) / (precision + recall), 4)
        if precision is not None
        and recall is not None
        and precision + recall
        else None
    )
    candidate_count = len(candidates)
    labelled_keys = {
        (item["event_sensor"], item["event_uid"]) for item in labels
    }
    return {
        "scenario_uid": scenario_uid,
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "true_negatives": true_negatives,
        "wrong_case_assignments": wrong_case_assignments,
        "incomplete_labels": incomplete_labels,
        "out_of_scope_label_count": out_of_scope_labels,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "candidate_event_count": candidate_count,
        "labelled_candidate_count": len(labelled_keys),
        "unlabelled_candidate_count": max(0, candidate_count - len(labelled_keys)),
        "calculation_version": "correlation-metrics-v1",
    }


def delete_evaluation_event_label(conn, scenario_uid, event_sensor, event_uid):
    """Delete a stored evaluation event label."""
    cur = conn.execute(
        """
        DELETE FROM evaluation_event_labels
        WHERE scenario_uid = ? AND event_sensor = ? AND event_uid = ?
        """,
        (scenario_uid, event_sensor, event_uid),
    )
    conn.commit()
    return cur.rowcount > 0


def upsert_evaluation_model_review(conn, review):
    """Add or update a evaluation model review record."""
    review_uid = review.get("review_uid") or f"eval-model-{uuid.uuid4().hex[:12]}"
    reviewed_at = utc_now()
    conn.execute(
        """
        INSERT INTO evaluation_model_reviews (
          review_uid, comparison_run_uid, profile_uid, anonymous_label,
          grounding_score, completeness_score, next_steps_score,
          uncertainty_score, usefulness_score, supported_claims,
          unsupported_claims, contradicted_claims, undecidable_claims,
          notes, reviewer_name, reviewed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(comparison_run_uid, profile_uid) DO UPDATE SET
          anonymous_label = excluded.anonymous_label,
          grounding_score = excluded.grounding_score,
          completeness_score = excluded.completeness_score,
          next_steps_score = excluded.next_steps_score,
          uncertainty_score = excluded.uncertainty_score,
          usefulness_score = excluded.usefulness_score,
          supported_claims = excluded.supported_claims,
          unsupported_claims = excluded.unsupported_claims,
          contradicted_claims = excluded.contradicted_claims,
          undecidable_claims = excluded.undecidable_claims,
          notes = excluded.notes,
          reviewer_name = excluded.reviewer_name,
          reviewed_at = excluded.reviewed_at
        """,
        (
            review_uid,
            review["comparison_run_uid"],
            review["profile_uid"],
            review["anonymous_label"],
            int(review["grounding_score"]),
            int(review["completeness_score"]),
            int(review["next_steps_score"]),
            int(review["uncertainty_score"]),
            int(review["usefulness_score"]),
            int(review.get("supported_claims", 0)),
            int(review.get("unsupported_claims", 0)),
            int(review.get("contradicted_claims", 0)),
            int(review.get("undecidable_claims", 0)),
            review.get("notes"),
            review["reviewer_name"],
            reviewed_at,
        ),
    )
    conn.commit()
    row = conn.execute(
        """
        SELECT * FROM evaluation_model_reviews
        WHERE comparison_run_uid = ? AND profile_uid = ?
        """,
        (review["comparison_run_uid"], review["profile_uid"]),
    ).fetchone()
    return dict(row) if row else None


def list_evaluation_model_reviews(conn, limit=500, comparison_run_uid=None):
    """List stored evaluation model reviews."""
    where = ""
    params = []
    if comparison_run_uid:
        where = "WHERE comparison_run_uid = ?"
        params.append(comparison_run_uid)
    params.append(int(limit))
    rows = conn.execute(
        f"""
        SELECT * FROM evaluation_model_reviews
        {where}
        ORDER BY reviewed_at DESC, review_uid
        LIMIT ?
        """,
        params,
    ).fetchall()
    return [dict(row) for row in rows]


def delete_evaluation_model_review(conn, review_uid):
    """Delete a stored evaluation model review."""
    cur = conn.execute(
        "DELETE FROM evaluation_model_reviews WHERE review_uid = ?",
        (review_uid,),
    )
    conn.commit()
    return cur.rowcount > 0


def evaluation_case_options(conn, limit=250):
    """Return cases that can be selected in the Evaluation Lab."""
    rows = conn.execute(
        """
        SELECT detections.case_uid, detections.id AS detection_id,
               detections.first_seen, detections.last_seen,
               detections.src_ip, detections.dest_ip,
               detections.detection_type, detections.sensor_state,
               responses.final_classification
        FROM detections
        LEFT JOIN responses ON responses.id = (
          SELECT MAX(response_rows.id)
          FROM responses AS response_rows
          WHERE response_rows.detection_id = detections.id
        )
        WHERE detections.case_uid IS NOT NULL
        ORDER BY detections.id DESC
        LIMIT ?
        """,
        (int(limit),),
    ).fetchall()
    return [dict(row) for row in rows]


def evaluation_overview(conn):
    """Summarize saved Evaluation Lab records."""
    counts = {}
    for name, table in {
        "scenarios": "evaluation_scenarios",
        "case_links": "evaluation_case_links",
        "event_labels": "evaluation_event_labels",
        "model_reviews": "evaluation_model_reviews",
        "comparison_runs": "ai_comparison_runs",
    }.items():
        counts[name] = conn.execute(
            f"SELECT COUNT(*) AS count FROM {table}"
        ).fetchone()["count"]
    experiment_rows = conn.execute(
        """
        SELECT experiment_type, COUNT(*) AS count
        FROM evaluation_scenarios
        GROUP BY experiment_type
        ORDER BY experiment_type
        """
    ).fetchall()
    counts["experiments"] = {
        row["experiment_type"]: row["count"] for row in experiment_rows
    }
    counts["recent_scenarios"] = list_evaluation_scenarios(conn, limit=8)
    return counts


def evaluation_export_bundle(conn, scenario_uid=None):
    """Build the complete Evaluation Lab export."""
    if scenario_uid:
        scenario = get_evaluation_scenario(conn, scenario_uid)
        scenarios = [scenario] if scenario else []
    else:
        scenarios = [
            get_evaluation_scenario(conn, item["scenario_uid"])
            for item in list_evaluation_scenarios(conn, limit=10000)
        ]
    scenario_uids = {item["scenario_uid"] for item in scenarios if item}
    model_reviews = list_evaluation_model_reviews(conn, limit=10000)
    if scenario_uid:
        linked_cases = {
            link["case_uid"]
            for scenario in scenarios
            for link in (scenario.get("case_links") or [])
        }
        comparison_uids = {
            row["comparison_uid"]
            for row in conn.execute(
                """
                SELECT comparison_uid, case_uid
                FROM ai_comparison_runs
                """
            ).fetchall()
            if row["case_uid"] in linked_cases
        }
        model_reviews = [
            review
            for review in model_reviews
            if review.get("comparison_run_uid") in comparison_uids
        ]
    correlation_metrics = {
        scenario["scenario_uid"]: evaluation_correlation_metrics(
            conn, scenario["scenario_uid"]
        )
        for scenario in scenarios
        if scenario
    }
    return {
        "schema_version": "evaluation-lab-v1",
        "exported_at": utc_now(),
        "scenarios": [item for item in scenarios if item],
        "correlation_metrics": correlation_metrics,
        "model_reviews": model_reviews,
    }

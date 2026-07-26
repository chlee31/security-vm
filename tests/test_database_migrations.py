import sqlite3
import tempfile
import unittest
from pathlib import Path

from app.database import init_db


class DatabaseMigrationTests(unittest.TestCase):
    def test_new_database_omits_retired_feature_schema(self):
        conn = init_db(":memory:")
        try:
            tables = {
                row["name"]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                ).fetchall()
            }
            self.assertNotIn("incident_evidence", tables)
            self.assertNotIn("firewall_blocks", tables)
            self.assertNotIn("allowlist", tables)
            self.assertNotIn("notification_events", tables)
            self.assertTrue(
                {
                    "evaluation_scenarios",
                    "evaluation_case_links",
                    "evaluation_event_labels",
                    "evaluation_model_reviews",
                }.issubset(tables)
            )
            alert_columns = {
                row["name"] for row in conn.execute("PRAGMA table_info(alerts)").fetchall()
            }
            report_columns = {
                row["name"] for row in conn.execute("PRAGMA table_info(ai_reports)").fetchall()
            }
            detection_columns = {
                row["name"]
                for row in conn.execute("PRAGMA table_info(detections)").fetchall()
            }
            self.assertNotIn("pcap_point", alert_columns)
            self.assertFalse(any(column.startswith("pcap_") for column in report_columns))
            self.assertNotIn("mitre_id", detection_columns)
            self.assertNotIn("mitre_name", detection_columns)
        finally:
            conn.close()

    def test_existing_packet_capture_history_is_not_destructively_dropped(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "legacy-capture.db"
            conn = sqlite3.connect(db_path)
            conn.execute(
                "CREATE TABLE incident_evidence (id INTEGER PRIMARY KEY, pcap_path TEXT)"
            )
            conn.execute(
                "INSERT INTO incident_evidence (id, pcap_path) VALUES (1, '/legacy/file.pcap')"
            )
            conn.commit()
            conn.close()

            migrated = init_db(db_path)
            try:
                row = migrated.execute(
                    "SELECT pcap_path FROM incident_evidence WHERE id = 1"
                ).fetchone()
                self.assertEqual(row["pcap_path"], "/legacy/file.pcap")
            finally:
                migrated.close()

    def test_retired_response_history_is_preserved_but_not_recreated(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "legacy-response.db"
            conn = sqlite3.connect(db_path)
            conn.execute(
                "CREATE TABLE firewall_blocks (id INTEGER PRIMARY KEY, ip_address TEXT)"
            )
            conn.execute(
                "INSERT INTO firewall_blocks (id, ip_address) VALUES (1, '203.0.113.10')"
            )
            conn.execute(
                "CREATE TABLE allowlist (id INTEGER PRIMARY KEY, ip_address TEXT)"
            )
            conn.execute(
                "INSERT INTO allowlist (id, ip_address) VALUES (1, '198.51.100.20')"
            )
            conn.execute(
                "CREATE TABLE notification_events (id INTEGER PRIMARY KEY, status TEXT)"
            )
            conn.execute(
                "INSERT INTO notification_events (id, status) VALUES (1, 'sent')"
            )
            conn.commit()
            conn.close()

            migrated = init_db(db_path)
            try:
                row = migrated.execute(
                    "SELECT ip_address FROM firewall_blocks WHERE id = 1"
                ).fetchone()
                self.assertEqual(row["ip_address"], "203.0.113.10")
                allowlist_row = migrated.execute(
                    "SELECT ip_address FROM allowlist WHERE id = 1"
                ).fetchone()
                self.assertEqual(allowlist_row["ip_address"], "198.51.100.20")
                notification_row = migrated.execute(
                    "SELECT status FROM notification_events WHERE id = 1"
                ).fetchone()
                self.assertEqual(notification_row["status"], "sent")
            finally:
                migrated.close()

    def test_legacy_sensor_tables_gain_community_id_before_runtime_queries(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "legacy.db"
            conn = sqlite3.connect(db_path)
            conn.executescript(
                """
                CREATE TABLE alerts (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  timestamp TEXT, src_ip TEXT, dest_ip TEXT
                );
                CREATE TABLE detections (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  first_alert_id INTEGER, first_seen TEXT, last_seen TEXT,
                  src_ip TEXT, dest_ip TEXT, detection_type TEXT
                );
                CREATE TABLE zeek_events (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  zeek_uid TEXT, log_type TEXT NOT NULL, timestamp TEXT NOT NULL,
                  raw_json TEXT NOT NULL, ingested_at TEXT NOT NULL
                );
                INSERT INTO alerts (timestamp, src_ip, dest_ip)
                VALUES ('2026-07-14T12:00:00+00:00', '192.168.11.50', '8.8.8.8');
                INSERT INTO detections (first_alert_id, first_seen, last_seen, src_ip, dest_ip, detection_type)
                VALUES (1, '2026-07-14T12:00:00+00:00', '2026-07-14T12:00:00+00:00', '192.168.11.50', '8.8.8.8', 'unknown');
                INSERT INTO zeek_events (zeek_uid, log_type, timestamp, raw_json, ingested_at)
                VALUES ('C1', 'notice', '2026-07-14T12:00:01+00:00', '{}', '2026-07-14T12:00:02+00:00');
                """
            )
            conn.close()

            migrated = init_db(db_path)
            try:
                for table in ("alerts", "detections", "zeek_events"):
                    columns = {
                        row["name"]
                        for row in migrated.execute(f"PRAGMA table_info({table})").fetchall()
                    }
                    self.assertIn("community_id", columns)
                alert_columns = {
                    row["name"]
                    for row in migrated.execute("PRAGMA table_info(alerts)").fetchall()
                }
                self.assertIn("event_fingerprint", alert_columns)
                checkpoint_table = migrated.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'suricata_ingest_checkpoints'"
                ).fetchone()
                self.assertIsNotNone(checkpoint_table)
                migrated.execute("SELECT community_id FROM detections LIMIT 1").fetchall()
                migrated.execute("SELECT community_id FROM alerts LIMIT 1").fetchall()
                self.assertEqual(
                    migrated.execute("SELECT event_uid FROM alerts WHERE id = 1").fetchone()["event_uid"],
                    "SUR-20260714-000001",
                )
                self.assertEqual(
                    migrated.execute("SELECT case_uid FROM detections WHERE id = 1").fetchone()["case_uid"],
                    "CASE-20260714-000001",
                )
                self.assertEqual(
                    migrated.execute("SELECT event_uid FROM zeek_events WHERE id = 1").fetchone()["event_uid"],
                    "ZEK-20260714-000001",
                )
            finally:
                migrated.close()

    def test_legacy_review_labels_migrate_without_rewriting_raw_ai_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "legacy-review-label.db"
            conn = init_db(db_path)
            raw_response = (
                '{"classification":"Human Review Required",'
                '"reason":"Original model wording must remain auditable."}'
            )
            conn.execute(
                """
                INSERT INTO ai_reports (classification, confidence, raw_response)
                VALUES ('Human Review Required', 'Low', ?)
                """,
                (raw_response,),
            )
            conn.execute(
                """
                INSERT INTO responses (final_classification, final_action)
                VALUES ('Human Review Required', 'human_review')
                """
            )
            conn.commit()
            conn.close()

            migrated = init_db(db_path)
            try:
                report = migrated.execute(
                    "SELECT classification, raw_response FROM ai_reports"
                ).fetchone()
                response = migrated.execute(
                    "SELECT final_classification, final_action FROM responses"
                ).fetchone()
                self.assertEqual(
                    report["classification"],
                    "Analyst Review Required",
                )
                self.assertEqual(report["raw_response"], raw_response)
                self.assertEqual(
                    response["final_classification"],
                    "Analyst Review Required",
                )
                self.assertEqual(response["final_action"], "human_review")
            finally:
                migrated.close()


if __name__ == "__main__":
    unittest.main()

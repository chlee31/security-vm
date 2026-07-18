import sqlite3
import tempfile
import unittest
from pathlib import Path

from app.database import init_db


class DatabaseMigrationTests(unittest.TestCase):
    def test_new_database_omits_retired_packet_capture_schema(self):
        conn = init_db(":memory:")
        try:
            tables = {
                row["name"]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                ).fetchall()
            }
            self.assertNotIn("incident_evidence", tables)
            alert_columns = {
                row["name"] for row in conn.execute("PRAGMA table_info(alerts)").fetchall()
            }
            report_columns = {
                row["name"] for row in conn.execute("PRAGMA table_info(ai_reports)").fetchall()
            }
            self.assertNotIn("pcap_point", alert_columns)
            self.assertFalse(any(column.startswith("pcap_") for column in report_columns))
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


if __name__ == "__main__":
    unittest.main()

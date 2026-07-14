import sqlite3
import tempfile
import unittest
from pathlib import Path

from app.database import init_db


class DatabaseMigrationTests(unittest.TestCase):
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

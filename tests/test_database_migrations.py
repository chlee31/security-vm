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
            finally:
                migrated.close()


if __name__ == "__main__":
    unittest.main()

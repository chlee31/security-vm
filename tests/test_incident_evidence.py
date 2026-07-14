from pathlib import Path
import tempfile
import unittest

from app.config import DEFAULT_CONFIG
from app.database import init_db, insert_zeek_event
from app.incident_evidence import create_incident_evidence


class IncidentEvidenceTests(unittest.TestCase):
    def test_create_incident_evidence_writes_manifest_and_zeek_context(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = str(Path(tmpdir) / "test.db")
            incident_root = str(Path(tmpdir) / "incidents")
            conn = init_db(db_path)
            conn.execute(
                """
                INSERT INTO alerts (timestamp, src_ip, dest_ip, src_port, dest_port, protocol, signature, raw_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                ("2026-07-10T12:00:00+00:00", "192.168.11.50", "8.8.8.8", 51515, 443, "TCP", "test alert", "{}"),
            )
            alert_id = conn.execute("SELECT id FROM alerts").fetchone()["id"]
            conn.execute(
                """
                INSERT INTO detections (first_alert_id, first_seen, last_seen, src_ip, dest_ip, detection_type)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (alert_id, "2026-07-10T12:00:00+00:00", "2026-07-10T12:00:01+00:00", "192.168.11.50", "8.8.8.8", "encrypted_traffic"),
            )
            detection_id = conn.execute("SELECT id FROM detections").fetchone()["id"]
            insert_zeek_event(
                conn,
                {
                    "log_type": "notice",
                    "timestamp": "2026-07-10T12:00:00+00:00",
                    "zeek_uid": "C1",
                    "source_ip": "192.168.11.50",
                    "destination_ip": "8.8.8.8",
                    "destination_port": 443,
                    "protocol": "tcp",
                    "event_name": "Test::Notice",
                    "message": "test zeek notice",
                    "raw_json": {"uid": "C1"},
                },
            )
            config = {
                **DEFAULT_CONFIG,
                "incident_evidence": {
                    **DEFAULT_CONFIG["incident_evidence"],
                    "root_directory": incident_root,
                },
            }
            evidence = create_incident_evidence(conn, config, detection_id)
            self.assertEqual(evidence["status"], "ready")
            self.assertTrue(Path(evidence["evidence_manifest_path"]).exists())
            self.assertTrue(Path(evidence["zeek_logs_path"]).exists())
            conn.close()


if __name__ == "__main__":
    unittest.main()

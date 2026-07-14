from pathlib import Path
import tempfile
import unittest

from app.database import (
    init_db,
    insert_zeek_event,
    upsert_zeek_checkpoint,
    zeek_telemetry_summary,
)


class ZeekTelemetryTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.conn = init_db(str(Path(self.tempdir.name) / "telemetry.db"))

    def tearDown(self):
        self.conn.close()
        self.tempdir.cleanup()

    def insert_event(self, log_type, uid, raw, **overrides):
        event = {
            "log_type": log_type,
            "timestamp": overrides.pop("timestamp", "2026-07-14T18:00:00+00:00"),
            "zeek_uid": uid,
            "source_ip": overrides.pop("source_ip", "192.168.11.50"),
            "source_port": overrides.pop("source_port", 51515),
            "destination_ip": overrides.pop("destination_ip", "8.8.8.8"),
            "destination_port": overrides.pop("destination_port", 443),
            "protocol": overrides.pop("protocol", "tcp"),
            "event_name": overrides.pop("event_name", log_type),
            "message": overrides.pop("message", f"{log_type} event"),
            "raw_json": raw,
            **overrides,
        }
        insert_zeek_event(self.conn, event)

    def test_summary_exposes_ingest_and_protocol_metadata(self):
        self.insert_event(
            "ssl",
            "C-SSL",
            {
                "server_name": "example.test",
                "version": "TLSv13",
                "cipher": "TLS_AES_256_GCM_SHA384",
                "validation_status": "ok",
                "sni_matches_cert": True,
                "established": True,
            },
        )
        self.insert_event(
            "files",
            "C-FILE",
            {
                "fuid": "F1",
                "source": "HTTP",
                "mime_type": "application/pdf",
                "seen_bytes": 4096,
                "missing_bytes": 0,
                "sha1": "abc123",
            },
        )
        self.insert_event(
            "dns",
            "C-DNS",
            {"query": "example.test", "qtype_name": "A", "rcode_name": "NOERROR"},
            message="example.test",
            destination_port=53,
            protocol="udp",
        )
        self.insert_event(
            "http",
            "C-HTTP",
            {"host": "example.test", "method": "GET", "status_code": 200},
        )
        upsert_zeek_checkpoint(
            self.conn, "ssl", "/opt/zeek/logs/current/ssl.log", 22, 8192
        )

        summary = zeek_telemetry_summary(self.conn)

        self.assertEqual(summary["total_events"], 4)
        self.assertEqual(summary["active_log_types"], 4)
        self.assertEqual(summary["event_counts"]["ssl"], 1)
        self.assertEqual(summary["checkpoints"][0]["offset"], 8192)
        self.assertEqual(summary["tls"]["versions"][0]["version"], "TLSv13")
        self.assertEqual(summary["tls"]["recent"][0]["server_name"], "example.test")
        self.assertEqual(summary["files"]["observed_bytes_recent"], 4096)
        self.assertEqual(summary["files"]["mime_types"][0]["mime_type"], "application/pdf")
        self.assertEqual(summary["dns"]["top_queries"][0]["query"], "example.test")
        self.assertEqual(summary["http"]["top_hosts"][0]["host"], "example.test")

    def test_recent_event_includes_correlated_case_uid(self):
        self.conn.execute(
            """
            INSERT INTO detections (case_uid, first_seen, last_seen, detection_type)
            VALUES ('CASE-20260714-000001', '2026-07-14T18:00:00+00:00',
                    '2026-07-14T18:00:00+00:00', 'encrypted_traffic')
            """
        )
        detection_id = self.conn.execute("SELECT id FROM detections").fetchone()["id"]
        self.insert_event("notice", "C-NOTICE", {"note": "Test::Notice"})
        event_id = self.conn.execute("SELECT id FROM zeek_events").fetchone()["id"]
        self.conn.execute(
            """
            INSERT INTO sensor_findings (
              detection_id, sensor, sensor_event_id, finding_type, finding_name
            ) VALUES (?, 'zeek', ?, 'notice', 'Test::Notice')
            """,
            (detection_id, event_id),
        )
        self.conn.commit()

        row = zeek_telemetry_summary(self.conn)["recent_events"][0]

        self.assertEqual(row["detection_id"], detection_id)
        self.assertEqual(row["case_uid"], "CASE-20260714-000001")


if __name__ == "__main__":
    unittest.main()

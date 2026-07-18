import json
import tempfile
import unittest
from pathlib import Path

from app.database import get_suricata_checkpoint, init_db, insert_alert
from app.normalizer import normalize_suricata_event
from app.suricata_reader import SuricataEveFollower


def eve_event(timestamp, signature="ET TEST Alert"):
    return {
        "timestamp": timestamp,
        "event_type": "alert",
        "flow_id": 1001,
        "src_ip": "192.168.11.50",
        "src_port": 50000,
        "dest_ip": "203.0.113.10",
        "dest_port": 443,
        "proto": "TCP",
        "alert": {
            "signature_id": 900001,
            "signature": signature,
            "category": "Test",
            "severity": 2,
        },
    }


class SuricataIngestTests(unittest.TestCase):
    def setUp(self):
        self.conn = init_db(":memory:")

    def tearDown(self):
        self.conn.close()

    def test_checkpoint_resumes_at_last_acknowledged_record(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "eve.json"
            first = eve_event("2026-07-18T10:00:00+00:00", "First")
            second = eve_event("2026-07-18T10:00:01+00:00", "Second")
            path.write_text(
                json.dumps(first) + "\n" + json.dumps(second) + "\n",
                encoding="utf-8",
            )

            follower = SuricataEveFollower(path, conn=self.conn, start_position="beginning", poll_seconds=0.01)
            records = follower.records()
            first_record = next(records)
            self.assertEqual(first_record.event["alert"]["signature"], "First")
            first_record.acknowledge()
            expected_offset = first_record.offset
            records.close()

            checkpoint = get_suricata_checkpoint(self.conn)
            self.assertEqual(checkpoint["offset"], expected_offset)

            resumed = SuricataEveFollower(path, conn=self.conn, start_position="end", poll_seconds=0.01)
            resumed_records = resumed.records()
            second_record = next(resumed_records)
            self.assertEqual(second_record.event["alert"]["signature"], "Second")
            second_record.acknowledge()
            resumed_records.close()

    def test_unacknowledged_record_is_replayed_after_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "eve.json"
            path.write_text(
                json.dumps(eve_event("2026-07-18T10:00:00+00:00", "Retry Me")) + "\n",
                encoding="utf-8",
            )

            follower = SuricataEveFollower(
                path,
                conn=self.conn,
                start_position="beginning",
                poll_seconds=0.01,
            )
            records = follower.records()
            first_attempt = next(records)
            records.close()

            checkpoint = get_suricata_checkpoint(self.conn)
            self.assertEqual(checkpoint["offset"], 0)

            resumed = SuricataEveFollower(
                path,
                conn=self.conn,
                start_position="end",
                poll_seconds=0.01,
            )
            resumed_records = resumed.records()
            replayed = next(resumed_records)
            self.assertEqual(replayed.event["alert"]["signature"], "Retry Me")
            self.assertEqual(replayed.offset, first_attempt.offset)
            replayed.acknowledge()
            resumed_records.close()

    def test_rotation_switches_to_replacement_file_from_start(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "eve.json"
            rotated = Path(directory) / "eve.json.1"
            path.write_text(json.dumps(eve_event("2026-07-18T10:00:00+00:00", "Old")) + "\n", encoding="utf-8")

            follower = SuricataEveFollower(path, conn=self.conn, start_position="beginning", poll_seconds=0.01)
            records = follower.records()
            old_record = next(records)
            old_record.acknowledge()

            path.rename(rotated)
            path.write_text(json.dumps(eve_event("2026-07-18T10:01:00+00:00", "New")) + "\n", encoding="utf-8")
            new_record = next(records)
            self.assertEqual(new_record.event["alert"]["signature"], "New")
            self.assertNotEqual(old_record.inode, new_record.inode)
            new_record.acknowledge()
            records.close()

    def test_content_fingerprint_prevents_duplicate_alert_rows(self):
        event = eve_event("2026-07-18T10:00:00+00:00")
        reordered = dict(reversed(list(event.items())))
        reordered["alert"] = dict(reversed(list(event["alert"].items())))
        first = normalize_suricata_event(event)
        second = normalize_suricata_event(reordered)

        first_id = insert_alert(self.conn, first)
        second_id = insert_alert(self.conn, second)

        self.assertEqual(first_id, second_id)
        self.assertFalse(first["_duplicate"])
        self.assertTrue(second["_duplicate"])
        self.assertEqual(
            self.conn.execute("SELECT COUNT(*) AS count FROM alerts").fetchone()["count"],
            1,
        )
        self.assertEqual(first["event_fingerprint"], second["event_fingerprint"])


if __name__ == "__main__":
    unittest.main()

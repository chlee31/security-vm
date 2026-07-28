import unittest

from app.ai_activity import ai_activity_callback
from app.database import (
    init_db,
    latest_ai_request_activity,
    latest_runtime_components,
    record_runtime_components,
)


class AIActivityTests(unittest.TestCase):
    def setUp(self):
        self.conn = init_db(":memory:")

    def tearDown(self):
        self.conn.close()

    def test_request_lifecycle_exposes_only_operational_metadata(self):
        activity_uid, progress = ai_activity_callback(
            self.conn,
            {"threat_intel": {}},
            "model_comparison",
            case_uid="CASE-TEST",
            detection_id=42,
            comparison_uid="cmp-test",
            anonymous_slot="B",
        )

        progress(
            "prompt_ready",
            {
                "prompt_chars": 1200,
                "prompt_bytes": 1210,
                "estimated_tokens": 300,
                "timeout_seconds": 90,
            },
        )
        progress("requesting")
        progress("complete", {"elapsed_ms": 2450, "parse_status": "valid_json"})

        rows = latest_ai_request_activity(self.conn)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["activity_uid"], activity_uid)
        self.assertEqual(rows[0]["anonymous_slot"], "B")
        self.assertEqual(rows[0]["status"], "complete")
        self.assertEqual(rows[0]["phase"], "complete")
        self.assertEqual(rows[0]["prompt_chars"], 1200)
        self.assertEqual(rows[0]["estimated_tokens"], 300)
        self.assertEqual(rows[0]["parse_status"], "valid_json")
        self.assertNotIn("prompt_text", rows[0])

    def test_failure_message_masks_configured_credentials(self):
        secret = "sensitive-test-key"
        _activity_uid, progress = ai_activity_callback(
            self.conn,
            {"threat_intel": {"otx_api_key": secret}},
            "initial",
        )
        progress(
            "failed",
            {
                "status": "failed",
                "error_message": f"Authorization token={secret}",
            },
        )

        row = latest_ai_request_activity(self.conn)[0]
        self.assertEqual(row["status"], "failed")
        self.assertNotIn(secret, row["error_message"])
        self.assertIn("***", row["error_message"])

    def test_launcher_component_heartbeat_is_reported(self):
        record_runtime_components(
            self.conn,
            [
                {
                    "component": "ai-worker",
                    "status": "running",
                    "pid": 1234,
                    "required": True,
                    "started_at": "2026-07-27T12:00:00+00:00",
                }
            ],
        )

        components = latest_runtime_components(self.conn)
        self.assertEqual(len(components), 1)
        self.assertEqual(components[0]["component"], "ai-worker")
        self.assertEqual(components[0]["status"], "running")
        self.assertTrue(components[0]["required"])


if __name__ == "__main__":
    unittest.main()

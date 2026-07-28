import unittest
from unittest.mock import MagicMock, patch

from app.database import detections_without_ai_reports, init_db, insert_detection
from app.main import run_ai_worker


def detection(timestamp, src_ip):
    return {
        "first_seen": timestamp,
        "last_seen": timestamp,
        "src_ip": src_ip,
        "dest_ip": "8.8.8.8",
        "src_port": 52000,
        "dest_port": 53,
        "protocol": "UDP",
        "sensor_state": "suricata_only",
        "agreement_state": "single_sensor",
        "correlation_method": "single_sensor",
        "correlation_confidence": 0.5,
        "detection_type": "dns_tunneling",
        "alert_count": 1,
        "unique_dest_ports": 1,
        "unique_dest_hosts": 1,
        "time_window_seconds": 0,
        "status": "developing",
    }


class AiWorkerTests(unittest.TestCase):
    def test_pending_query_honors_correlation_delay_and_order(self):
        conn = init_db(":memory:")
        try:
            first_id = insert_detection(
                conn,
                detection("2026-07-27T18:00:00-04:00", "192.168.11.10"),
            )
            second_id = insert_detection(
                conn,
                detection("2026-07-27T18:00:01-04:00", "192.168.11.11"),
            )
            conn.execute(
                "UPDATE detections SET created_at = datetime('now', '-30 seconds')"
            )
            conn.commit()

            oldest = detections_without_ai_reports(
                conn,
                limit=2,
                minimum_age_seconds=5,
            )
            newest = detections_without_ai_reports(
                conn,
                limit=2,
                newest_first=True,
                minimum_age_seconds=5,
            )

            self.assertEqual(
                [row["detection_id"] for row in oldest],
                [first_id, second_id],
            )
            self.assertEqual(
                [row["detection_id"] for row in newest],
                [second_id, first_id],
            )
            conn.execute(
                "UPDATE detections SET created_at = CURRENT_TIMESTAMP WHERE id = ?",
                (second_id,),
            )
            conn.commit()
            delayed = detections_without_ai_reports(
                conn,
                limit=2,
                minimum_age_seconds=5,
            )
            self.assertEqual(
                [row["detection_id"] for row in delayed],
                [first_id],
            )
        finally:
            conn.close()

    @patch("app.main.assess_detection")
    @patch("app.main.assessment_inputs_from_row")
    @patch("app.main.detections_without_ai_reports")
    @patch("app.main.insert_app_event")
    @patch("app.main.init_db")
    @patch("app.main.load_config")
    @patch("app.main.model_metadata")
    def test_worker_assesses_one_durable_pending_case(
        self,
        model_metadata,
        load_config,
        init_db,
        _insert_app_event,
        pending_rows,
        assessment_inputs,
        assess_detection,
    ):
        conn = MagicMock()
        init_db.return_value = conn
        load_config.return_value = {"database": {"path": ":memory:"}}
        model_metadata.return_value = {
            "model_identity": "test:model",
            "ai_profile_uid": "ai-test",
        }
        row = {"detection_id": 42, "alert_id": 7}
        pending_rows.side_effect = [[row], KeyboardInterrupt()]
        alert = {"src_ip": "192.168.11.50", "dest_ip": "8.8.8.8"}
        queued_detection = {"sensor_state": "multi_sensor"}
        assessment_inputs.return_value = (alert, queued_detection)

        with self.assertRaises(KeyboardInterrupt):
            run_ai_worker("config.yaml", poll_seconds=0, correlation_delay_seconds=0)

        assess_detection.assert_called_once_with(
            conn,
            "config.yaml",
            alert,
            queued_detection,
            7,
            42,
        )
        conn.close.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()

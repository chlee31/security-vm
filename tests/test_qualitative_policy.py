import json
import unittest

from app.ai_client import AI_RESPONSE_SCHEMA, build_prompt, normalize_report
from app.database import init_db, insert_ai_report, insert_detection, insert_response
from app.decision_engine import decide


class QualitativePolicyTests(unittest.TestCase):
    def setUp(self):
        self.conn = init_db(":memory:")
        self.alert = {
            "timestamp": "2026-07-24T12:00:00+00:00",
            "src_ip": "192.168.11.50",
            "dest_ip": "8.8.8.8",
            "src_port": 52000,
            "dest_port": 53,
            "protocol": "UDP",
            "signature": "DNS anomaly",
            "category": "Potentially Bad Traffic",
            "priority": 2,
        }
        self.detection = {
            "first_seen": self.alert["timestamp"],
            "last_seen": self.alert["timestamp"],
            "src_ip": self.alert["src_ip"],
            "dest_ip": self.alert["dest_ip"],
            "src_port": self.alert["src_port"],
            "dest_port": self.alert["dest_port"],
            "protocol": self.alert["protocol"],
            "sensor_state": "multi_sensor",
            "agreement_state": "supporting",
            "correlation_method": "community_id",
            "correlation_confidence": 0.95,
            "detection_type": "dns_tunneling",
            "alert_count": 2,
            "unique_dest_ports": 1,
            "unique_dest_hosts": 1,
            "time_window_seconds": 60,
            "status": "correlated",
        }

    def tearDown(self):
        self.conn.close()

    def test_response_contract_has_no_score_or_adjustment(self):
        properties = AI_RESPONSE_SCHEMA["properties"]
        self.assertNotIn("risk_adjustment", properties)
        self.assertNotIn("score", properties)
        self.assertNotIn("risk_adjustment", AI_RESPONSE_SCHEMA["required"])

    def test_prompt_contains_evidence_but_no_operational_score(self):
        prompt = build_prompt(
            self.alert,
            self.detection,
            {
                "sensor_fusion": {
                    "findings": [
                        {"sensor": "suricata", "finding_name": "DNS anomaly"},
                        {"sensor": "zeek", "finding_name": "DNS::Tunneling"},
                    ]
                },
                "threat_intel": {
                    "dest_ip": {
                        "indicator": "8.8.8.8",
                        "providers": [{"source": "otx", "reputation": "benign"}],
                    }
                },
                "asset_context": {
                    "matched_asset": {
                        "ip_address": "192.168.11.50",
                        "name": "Test workstation",
                        "device_type": "desktop",
                        "asset_score": 10,
                    }
                },
            },
        )
        lower = prompt.lower()
        self.assertIn("suricata", lower)
        self.assertIn("zeek", lower)
        self.assertIn("threat_intel", lower)
        self.assertNotIn("asset_score", lower)
        self.assertNotIn("python_initial_score", lower)
        self.assertNotIn("risk_adjustment", lower)
        self.assertNotIn("final_score", lower)

    def test_normalization_discards_legacy_adjustment(self):
        report = normalize_report(
            {
                "classification": "Dangerous",
                "confidence": "High",
                "risk_adjustment": 10,
                "reason": "Threat intelligence and both sensors support escalation.",
                "recommended_action": "escalate",
            }
        )
        self.assertNotIn("risk_adjustment", report)
        self.assertEqual(report["classification"], "Dangerous")

    def test_classifications_map_to_qualitative_actions(self):
        expected = {
            "Safe": "log_only",
            "Human Review Required": "human_review",
            "Dangerous": "escalate",
        }
        for classification, action in expected.items():
            with self.subTest(classification=classification):
                result = decide(
                    self.conn,
                    {"system": {"mode": "alert_only"}},
                    self.alert,
                    self.detection,
                    {"classification": classification},
                )
                self.assertEqual(result["final_classification"], classification)
                self.assertEqual(result["final_action"], action)
                self.assertNotIn("final_score", result)

    def test_invalid_classification_defaults_to_human_review(self):
        result = decide(
            self.conn,
            {},
            self.alert,
            self.detection,
            {"classification": "maybe"},
        )
        self.assertEqual(result["final_classification"], "Human Review Required")
        self.assertEqual(result["final_action"], "human_review")

    def test_material_sensor_dispute_forces_human_review(self):
        result = decide(
            self.conn,
            {},
            self.alert,
            {**self.detection, "agreement_state": "disputed"},
            {"classification": "Safe"},
        )
        self.assertEqual(result["final_classification"], "Human Review Required")
        self.assertTrue(result["forced_review"])

    def test_new_database_schema_and_rows_have_no_operational_score_fields(self):
        detection_id = insert_detection(self.conn, self.detection)
        insert_ai_report(
            self.conn,
            detection_id,
            {
                "classification": "Safe",
                "confidence": "High",
                "risk_adjustment": -10,
                "reason": "No malicious evidence was found.",
            },
        )
        insert_response(
            self.conn,
            {
                "detection_id": detection_id,
                "final_classification": "Safe",
                "final_action": "log_only",
                "response_method": "qualitative_evidence_workflow",
                "response_status": "log_only",
            },
        )
        expected_absent = {
            "detections": {"python_initial_score"},
            "ai_reports": {"risk_adjustment"},
            "ai_assessments": {"risk_adjustment"},
            "ai_comparison_candidates": {"risk_adjustment"},
            "responses": {"final_score"},
            "assets": {"asset_score"},
            "analyst_reviews": {"original_score", "analyst_score"},
        }
        for table, retired_fields in expected_absent.items():
            columns = {
                row["name"]
                for row in self.conn.execute(f"PRAGMA table_info({table})").fetchall()
            }
            self.assertTrue(retired_fields.isdisjoint(columns), table)
        self.assertIsNone(
            self.conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'score_breakdowns'"
            ).fetchone()
        )


if __name__ == "__main__":
    unittest.main()

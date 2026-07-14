import unittest

from app.ai_client import build_prompt, normalize_risk_adjustment
from app.database import init_db, insert_alert, insert_detection
from app.decision_engine import classify_score, decide
from app.risk_score import deterministic_score


class ScoringPolicyTests(unittest.TestCase):
    def setUp(self):
        self.conn = init_db(":memory:")
        self.alert = {
            "timestamp": "2026-07-14T12:00:00+00:00",
            "src_ip": "192.168.11.50",
            "dest_ip": "8.8.8.8",
            "src_port": 50000,
            "dest_port": 53,
            "protocol": "udp",
            "signature": "DNS tunnel",
            "category": "Command and Control",
            "priority": 1,
        }
        self.detection = {
            "detection_type": "dns_tunneling",
            "alert_count": 40,
            "unique_dest_ports": 50,
            "unique_dest_hosts": 20,
            "time_window_seconds": 60,
            "mitre_id": "T1071.004",
            "mitre_name": "Application Layer Protocol: DNS",
            "sensor_state": "multi_sensor",
            "agreement_state": "supporting",
            "correlation_method": "community_id",
            "asset_context": {"asset_score": 10, "asset_match": "src_ip"},
        }

    def test_six_categories_cap_python_at_90(self):
        findings = [
            {"sensor": "suricata", "severity": 1},
            {"sensor": "zeek", "severity": 2},
        ]
        evidence = {
            "threat_intel": {
                "src_ip": {
                    "matches": [
                        {"source": "threatfox", "confidence": 95, "category": "malware c2"},
                        {"source": "urlhaus", "confidence": 90, "category": "malicious"},
                        {"source": "ipsum", "confidence": 80, "category": "botnet"},
                    ]
                }
            }
        }
        result = deterministic_score(self.alert, self.detection, findings, evidence)

        self.assertEqual(result["python_score"], 90)
        self.assertEqual(result["sensor_severity"], 20)
        self.assertEqual(result["behavior_correlation"], 20)
        self.assertEqual(result["threat_intelligence"], 20)
        self.assertEqual(result["mitre_relevance"], 10)
        self.assertEqual(result["asset_direction"], 10)
        self.assertEqual(result["sensor_corroboration"], 10)

    def test_outcome_boundaries(self):
        expected = {
            0: "Safe",
            29: "Safe",
            30: "Human Review Required",
            69: "Human Review Required",
            70: "High Risk",
            84: "High Risk",
            85: "Dangerous",
            100: "Dangerous",
        }
        for score, classification in expected.items():
            with self.subTest(score=score):
                self.assertEqual(classify_score(score), classification)

    def test_ai_adjustment_is_independently_clamped(self):
        self.assertEqual(normalize_risk_adjustment(-999), -10)
        self.assertEqual(normalize_risk_adjustment(999), 10)

    def test_material_dispute_forces_review(self):
        detection = {**self.detection, "agreement_state": "disputed"}
        findings = [
            {"sensor": "suricata", "severity": 1},
            {"sensor": "zeek", "severity": 1},
        ]
        breakdown = deterministic_score(self.alert, detection, findings, {})
        detection.update(
            python_initial_score=90,
            forced_review=breakdown["forced_review"],
            forced_review_reason=breakdown["forced_review_reason"],
        )
        response = decide(
            self.conn,
            {"system": {"mode": "prevention"}},
            self.alert,
            detection,
            {"classification": "Dangerous", "confidence": "High", "risk_adjustment": 10},
        )
        self.assertEqual(response["final_classification"], "Human Review Required")
        self.assertEqual(response["final_action"], "human_review")

    def test_prompt_excludes_packet_summary_and_uses_ten_point_limit(self):
        prompt = build_prompt(self.alert, self.detection, {}, pcap_summary="SECRET PACKET SUMMARY")
        self.assertNotIn("SECRET PACKET SUMMARY", prompt)
        self.assertIn("integer from -10 to 10", prompt)

    def test_inserted_rows_receive_stable_public_uids(self):
        alert = dict(self.alert)
        alert_id = insert_alert(self.conn, alert)
        detection = {
            **self.detection,
            "first_alert_id": alert_id,
            "first_seen": alert["timestamp"],
            "last_seen": alert["timestamp"],
            "src_ip": alert["src_ip"],
            "dest_ip": alert["dest_ip"],
            "python_initial_score": 0,
        }
        detection_id = insert_detection(self.conn, detection)
        self.assertEqual(alert["event_uid"], "SUR-20260714-000001")
        self.assertEqual(detection["case_uid"], "CASE-20260714-000001")
        self.assertEqual(alert_id, 1)
        self.assertEqual(detection_id, 1)


if __name__ == "__main__":
    unittest.main()

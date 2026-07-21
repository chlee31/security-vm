import unittest
from unittest.mock import MagicMock, patch

from app.ai_client import (
    AI_RESPONSE_SCHEMA,
    ask_ai_model,
    build_prompt,
    normalize_report,
    normalize_risk_adjustment,
    parse_model_response,
)
from app.database import (
    init_db,
    insert_alert,
    insert_detection,
    insert_score_breakdown,
    update_detection_python_score,
)
from app.decision_engine import classify_score, decide
from app.risk_score import cap_python_score, deterministic_score


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

    def test_five_categories_cap_python_at_80_without_mitre_points(self):
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

        self.assertEqual(result["python_score"], 80)
        self.assertEqual(result["sensor_severity"], 20)
        self.assertEqual(result["behavior_correlation"], 20)
        self.assertEqual(result["threat_intelligence"], 20)
        self.assertNotIn("mitre_relevance", result)
        self.assertEqual(result["asset_direction"], 10)
        self.assertEqual(result["sensor_corroboration"], 10)
        self.assertEqual(result["policy_version"], "deterministic-score-v2")
        self.assertEqual(sum(result["category_maximums"].values()), 80)
        self.assertEqual(cap_python_score(999), 80)

    def test_mitre_mapping_does_not_change_deterministic_score(self):
        mapped = deterministic_score(self.alert, self.detection, [], {})
        unmapped = deterministic_score(
            self.alert,
            {**self.detection, "mitre_id": None, "mitre_name": None},
            [],
            {},
        )
        self.assertEqual(mapped["python_score"], unmapped["python_score"])
        self.assertEqual(mapped["details"], unmapped["details"])

    def test_zeek_observable_matches_contribute_to_threat_intelligence(self):
        evidence = {
            "threat_intel": {
                "zeek_observables": {
                    "items": [{
                        "indicator": "c2.example.test",
                        "indicator_type": "domain",
                        "log_types": ["dns", "ssl"],
                        "matches": [{
                            "source": "threatfox",
                            "confidence": 95,
                            "category": "botnet_c2",
                        }],
                    }]
                }
            }
        }

        result = deterministic_score(self.alert, self.detection, [], evidence)

        self.assertGreater(result["threat_intelligence"], 0)
        self.assertIn(
            "threatfox",
            result["details"]["threat_intelligence"]["provider_points"],
        )

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

    def test_model_response_parser_accepts_fenced_json(self):
        parsed = parse_model_response(
            '```json\n{"classification":"Safe","confidence":"Medium","risk_adjustment":-2}\n```'
        )
        self.assertEqual(parsed["classification"], "Safe")

    def test_model_response_parser_accepts_preface_and_normalizes_numeric_confidence(self):
        parsed = parse_model_response(
            'Assessment follows:\n{"classification":"Dangerous","confidence":80,"risk_adjustment":4}'
        )
        normalized = normalize_report(parsed)
        self.assertEqual(normalized["classification"], "Dangerous")
        self.assertEqual(normalized["confidence"], "High")

    def test_model_response_parser_recovers_complete_fields_from_truncated_json(self):
        parsed = parse_model_response(
            '{"classification":"Safe","confidence":"Medium","risk_adjustment":-2,'
            '"summary":"Useful narrative","next_steps":[{"step":"cut off'
        )
        self.assertTrue(parsed["_partial_response"])
        self.assertEqual(parsed["summary"], "Useful narrative")

    def test_model_response_normalizes_object_next_steps(self):
        normalized = normalize_report(
            {
                "classification": "Human Review Required",
                "confidence": "Medium",
                "next_steps": [{"step": "Inspect Zeek ssl.log for the named server."}],
            }
        )
        self.assertEqual(normalized["next_steps"], ["Inspect Zeek ssl.log for the named server."])

    def test_alternate_threat_summary_schema_is_mapped_for_display(self):
        normalized = normalize_report(
            {
                "threat_summary": {
                    "ip_address": "203.0.113.10",
                    "port_range": "443/TCP",
                    "activity_pattern": "Repeated encrypted connections",
                },
                "risk_assessment": {"severity_level": "Medium", "confidence_score": 0.65},
                "recommendations": [{"action": "Inspect Zeek ssl.log", "rationale": "Unusual recurrence"}],
            }
        )
        self.assertEqual(normalized["classification"], "Human Review Required")
        self.assertEqual(normalized["confidence"], "Medium")
        self.assertEqual(normalized["summary"], "Repeated encrypted connections")
        self.assertEqual(normalized["next_steps"], ["Inspect Zeek ssl.log"])

    def test_sensor_record_echo_is_not_treated_as_analysis(self):
        normalized = normalize_report(
            {
                "event_type": "alert",
                "src_ip": "192.168.11.50",
                "dest_ip": "8.8.8.8",
                "alert": {"signature": "Test signature"},
            }
        )
        self.assertEqual(normalized["classification"], "Human Review Required")
        self.assertIn("copied normalized sensor evidence", normalized["summary"])

    @patch("app.ai_client.requests.post")
    def test_ai_request_enforces_schema_and_non_streaming_output(self, mock_post):
        response = MagicMock()
        response.json.return_value = {
            "response": '{"classification":"Safe","confidence":"High","risk_adjustment":-2,'
            '"reason":"Routine traffic","summary":"Routine traffic","who":"client",'
            '"what":"request","when":"case window","where":"network boundary",'
            '"why":"known behavior","how":"sensor metadata",'
            '"next_steps":["Validate the signature","Confirm the endpoint role"],'
            '"recommended_action":"log_only"}'
        }
        mock_post.return_value = response
        report = ask_ai_model(
            {"ai_model": {"host": "http://127.0.0.1:11434", "model": "test", "timeout_seconds": 5}},
            self.alert,
            self.detection,
            {"sensor_fusion": {"findings": [{"raw_event": "large raw sensor object", "sensor": "suricata"}]}},
        )
        request_body = mock_post.call_args.kwargs["json"]
        self.assertFalse(request_body["stream"])
        self.assertEqual(request_body["format"], AI_RESPONSE_SCHEMA)
        self.assertNotIn("large raw sensor object", request_body["prompt"])
        self.assertEqual(report["summary"], "Routine traffic")
        self.assertEqual(report["threat_intel_analysis"]["influence"], "unavailable")
        self.assertEqual(
            report["threat_intel_analysis"]["providers"]["virustotal"],
            "The model did not provide a source-specific interpretation.",
        )

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
            {"system": {"mode": "analysis"}},
            self.alert,
            detection,
            {"classification": "Dangerous", "confidence": "High", "risk_adjustment": 10},
        )
        self.assertEqual(response["final_classification"], "Human Review Required")
        self.assertEqual(response["final_action"], "human_review")

    def test_decision_actions_are_passive_analyst_workflows(self):
        expected = {
            29: ("Safe", "log_only"),
            30: ("Human Review Required", "human_review"),
            70: ("High Risk", "investigate"),
            85: ("Dangerous", "escalate"),
        }
        for score, outcome in expected.items():
            with self.subTest(score=score):
                response = decide(
                    self.conn,
                    {"system": {"mode": "analysis"}},
                    self.alert,
                    {**self.detection, "python_initial_score": score},
                )
                self.assertEqual((response["final_classification"], response["final_action"]), outcome)
                self.assertIsNone(response["target_ip"])
                self.assertEqual(response["response_method"], "analyst_workflow")

    def test_prompt_uses_case_explanation_contract_and_ten_point_limit(self):
        prompt = build_prompt(self.alert, self.detection, {"raw_event": "duplicated raw sensor payload"})
        self.assertIn("integer from -10 to 10", prompt)
        for field in ("who", "what", "when", "where", "why", "how", "next_steps", "threat_intel_analysis"):
            self.assertIn(field, prompt)
        self.assertIn("descriptive context only", prompt)
        self.assertIn("must not independently increase risk", prompt)
        self.assertNotIn("duplicated raw sensor payload", prompt)
        self.assertIn("validates against this exact schema", prompt)

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

        update_detection_python_score(self.conn, detection_id, 999)
        stored_detection = self.conn.execute(
            "SELECT python_initial_score FROM detections WHERE id = ?",
            (detection_id,),
        ).fetchone()
        self.assertEqual(stored_detection["python_initial_score"], 80)

        breakdown = deterministic_score(self.alert, self.detection, [], {})
        insert_score_breakdown(
            self.conn,
            detection_id,
            breakdown,
            llm_adjustment_raw=999,
            llm_adjustment_applied=10,
            provisional_score=999,
        )
        stored_breakdown = self.conn.execute(
            "SELECT python_score, mitre_relevance, provisional_score FROM score_breakdowns"
        ).fetchone()
        self.assertEqual(dict(stored_breakdown), {
            "python_score": breakdown["python_score"],
            "mitre_relevance": 0,
            "provisional_score": 90,
        })


if __name__ == "__main__":
    unittest.main()

import hashlib
import json
import unittest
from unittest.mock import MagicMock, patch

from app.ai_client import (
    AI_RESPONSE_SCHEMA,
    ask_ai_model,
    build_prompt_audit,
    compact_ai_evidence_with_manifest,
    enforce_evidence_grounding,
)
from app.database import (
    ai_run_audits_for_detection,
    investigation_detail,
    init_db,
    insert_ai_report,
    sensor_findings_for_detection,
    upsert_ai_run_audit,
)


class AIAuditTests(unittest.TestCase):
    def setUp(self):
        self.config = {
            "ai_model": {
                "host": "http://127.0.0.1:11434",
                "model": "audit-test",
                "timeout_seconds": 5,
            }
        }
        self.alert = {
            "event_uid": "SUR-20260724-000001",
            "timestamp": "2026-07-24T12:00:00+00:00",
            "src_ip": "192.168.11.50",
            "dest_ip": "8.8.8.8",
            "src_port": 50000,
            "dest_port": 53,
            "protocol": "UDP",
            "signature": "Audit test",
        }
        self.detection = {
            "case_uid": "CASE-20260724-000001",
            "first_seen": self.alert["timestamp"],
            "last_seen": self.alert["timestamp"],
            "detection_type": "dns_tunneling",
            "sensor_state": "multi_sensor",
            "agreement_state": "corroborated",
            "correlation_method": "community_id",
            "community_id": "1:test",
            "alert_count": 2,
            "unique_dest_ports": 1,
        }

    def test_compaction_records_every_bound_and_sensitive_omission(self):
        compacted, omissions = compact_ai_evidence_with_manifest(
            {
                "api_key": "must-not-leak",
                "items": list(range(30)),
                "long_text": "x" * 2100,
            }
        )
        self.assertNotIn("api_key", compacted)
        self.assertEqual(len(compacted["items"]), 25)
        self.assertTrue(compacted["long_text"].endswith("[truncated by Python]"))
        reasons = {item["reason"] for item in omissions}
        self.assertEqual(
            reasons,
            {"raw_or_sensitive_field", "list_item_limit", "string_character_limit"},
        )

    @patch("app.ai_client.requests.post")
    def test_model_request_retains_exact_prompt_package_and_response_proof(self, mock_post):
        model_output = {
            "classification": "Analyst Review Required",
            "confidence": "Medium",
            "reason": "The supplied sensor records require validation.",
            "summary": "Suricata and Zeek observed related DNS activity.",
            "who": "192.168.11.50",
            "what": "Repeated DNS activity",
            "when": "2026-07-24T12:00:00+00:00",
            "where": "192.168.11.50 to 8.8.8.8",
            "why": "Two sensors supplied related metadata.",
            "how": "Community ID correlation",
            "next_steps": ["Inspect the Zeek DNS query", "Validate the Suricata rule"],
            "threat_intel_analysis": {
                "overall": "No active match",
                "influence": "none",
                "providers": {
                    name: "No match"
                    for name in (
                        "otx", "threatfox", "urlhaus", "sslbl", "spamhaus_drop",
                        "openphish", "ipsum", "feodo", "virustotal",
                    )
                },
            },
            "evidence_review": {
                "received_sections": ["event_context", "evidence_context"],
                "evidence_used": ["SUR-20260724-000001", "Zeek dns.log"],
                "missing_or_ambiguous": ["No endpoint telemetry"],
                "review_method": "Compared correlated sensor metadata and threat intelligence.",
            },
            "recommended_action": "human_review",
        }
        raw_response = json.dumps(model_output)
        response = MagicMock()
        response.json.return_value = {"response": raw_response, "prompt_eval_count": 1234}
        mock_post.return_value = response

        phases = []
        report = ask_ai_model(
            self.config,
            self.alert,
            self.detection,
            {
                "sensor_fusion": {
                    "findings": [{"event_uid": "SUR-20260724-000001", "raw_json": "secret raw"}]
                },
                "credentials": {"api_key": "must-not-leak"},
            },
            progress_callback=lambda phase, details: phases.append((phase, details)),
        )
        sent = mock_post.call_args.kwargs["json"]
        self.assertEqual(sent["format"], AI_RESPONSE_SCHEMA)
        self.assertEqual(sent["options"]["temperature"], 0.0)
        self.assertEqual(sent["options"]["seed"], 42)
        self.assertEqual(report["audit_prompt_text"], sent["prompt"])
        self.assertNotIn("must-not-leak", report["audit_prompt_text"])
        self.assertEqual(
            report["prompt_sha256"],
            hashlib.sha256(sent["prompt"].encode("utf-8")).hexdigest(),
        )
        self.assertEqual(
            report["audit_response_sha256"],
            hashlib.sha256(raw_response.encode("utf-8")).hexdigest(),
        )
        self.assertEqual(report["audit_parse_status"], "valid_json")
        self.assertEqual(report["audit_response_metrics"]["prompt_eval_count"], 1234)
        self.assertIn("estimated_fits_configured_context", report["audit_request_options"])
        self.assertIn("Zeek dns.log", report["evidence_review"]["evidence_used"])
        self.assertEqual(
            [phase for phase, _details in phases],
            [
                "preparing",
                "prompt_ready",
                "requesting",
                "response_received",
                "parsing",
                "complete",
            ],
        )
        self.assertNotIn("prompt", phases[1][1])

    def test_python_rejects_unsupported_threat_intel_and_placeholder_verdict(self):
        report = {
            "classification": "Dangerous",
            "confidence": "High",
            "reason": "Threat intelligence supports malicious activity.",
            "recommended_action": "escalate",
            "who": "Analyst",
            "what": "Unknown",
            "when": "Unknown",
            "where": "Network traffic",
            "why": "Unknown",
            "how": "Unknown",
            "threat_intel_analysis": {
                "overall": "Dangerous",
                "influence": "supports_malicious",
                "providers": {},
            },
            "evidence_review": {"evidence_used": []},
        }
        package = {
            "evidence_context": {
                "threat_intel": {
                    "dest_ip": {
                        "providers": [
                            {
                                "name": "threatfox",
                                "enabled": True,
                                "status": "ready",
                                "result": "no_match",
                                "matches": [],
                            }
                        ]
                    }
                }
            }
        }

        grounded = enforce_evidence_grounding(report, package)

        self.assertEqual(grounded["classification"], "Analyst Review Required")
        self.assertEqual(grounded["confidence"], "Low")
        self.assertEqual(grounded["recommended_action"], "human_review")
        self.assertEqual(grounded["threat_intel_analysis"]["influence"], "none")
        self.assertTrue(grounded["grounding_review"]["corrected"])

    def test_sqlite_audit_and_raw_sensor_provenance_are_retrievable(self):
        conn = init_db(":memory:")
        try:
            conn.execute(
                """
                INSERT INTO alerts (
                  id, event_uid, timestamp, src_ip, dest_ip, src_port, dest_port,
                  protocol, signature, raw_json
                ) VALUES (1, 'SUR-20260724-000001', ?, '192.168.11.50', '8.8.8.8',
                          50000, 53, 'UDP', 'Audit test', ?)
                """,
                (self.alert["timestamp"], json.dumps({"src_ip": "192.168.11.50", "dest_port": 53})),
            )
            conn.execute(
                """
                INSERT INTO detections (
                  id, case_uid, first_alert_id, first_seen, last_seen, src_ip, dest_ip,
                  detection_type
                ) VALUES (1, 'CASE-20260724-000001', 1, ?, ?, '192.168.11.50',
                          '8.8.8.8', 'dns_tunneling')
                """,
                (self.alert["timestamp"], self.alert["timestamp"]),
            )
            conn.execute(
                """
                INSERT INTO sensor_findings (
                  detection_id, sensor, sensor_event_id, finding_type, finding_name,
                  severity, confidence, raw_event
                ) VALUES (1, 'suricata', 1, 'alert', 'Audit test', 2, 0.8, '{}')
                """
            )
            conn.commit()

            _prompt, report = build_prompt_audit(
                self.config,
                self.alert,
                self.detection,
                {"sensor_fusion": {"findings": [{"event_uid": "SUR-20260724-000001"}]}},
            )
            report.update(
                classification="Analyst Review Required",
                confidence="Low",
                reason="Audit test",
                raw_response=json.dumps(
                    {
                        "classification": "Analyst Review Required",
                        "confidence": "Low",
                        "reason": "The stored sensor evidence requires analyst validation.",
                        "summary": "A DNS-related case was assembled from sensor metadata.",
                        "next_steps": [
                            "Inspect the related Zeek DNS records.",
                            "Validate the Suricata signature.",
                        ],
                        "recommended_action": "human_review",
                    }
                ),
                audit_status="complete",
                audit_parse_status="valid_json",
            )
            report_id = insert_ai_report(conn, 1, report)
            upsert_ai_run_audit(conn, 1, report, report_id, "initial")

            audits = ai_run_audits_for_detection(conn, 1)
            self.assertEqual(len(audits), 1)
            self.assertEqual(audits[0]["prompt_text"], report["audit_prompt_text"])
            self.assertEqual(audits[0]["source_map"]["event_context"]["event_uid"], self.alert["event_uid"])
            self.assertEqual(
                audits[0]["model_response"]["summary"],
                "A DNS-related case was assembled from sensor metadata.",
            )
            self.assertEqual(
                audits[0]["model_response"]["next_steps"],
                [
                    "Inspect the related Zeek DNS records.",
                    "Validate the Suricata signature.",
                ],
            )

            finding = sensor_findings_for_detection(conn, 1)[0]
            self.assertEqual(finding["source_table"], "alerts")
            self.assertEqual(finding["source_record_id"], 1)
            self.assertEqual(finding["raw_record"]["dest_port"], 53)
            self.assertEqual(len(finding["raw_record_sha256"]), 64)
        finally:
            conn.close()

    def test_unassessed_investigation_exposes_empty_ai_state(self):
        conn = init_db(":memory:")
        try:
            conn.execute(
                """
                INSERT INTO detections (
                  id, case_uid, first_seen, last_seen, src_ip, dest_ip,
                  detection_type
                ) VALUES (1, 'CASE-PENDING', ?, ?, '192.168.11.50',
                          '8.8.8.8', 'dns_tunneling')
                """,
                (self.alert["timestamp"], self.alert["timestamp"]),
            )
            conn.commit()

            detail = investigation_detail(conn, 1)

            self.assertFalse(detail["ai_report_available"])
            self.assertFalse(detail["decision_available"])
            self.assertIsNone(detail["ai_model_identity"])
            self.assertEqual(detail["ai_next_steps"], [])
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()

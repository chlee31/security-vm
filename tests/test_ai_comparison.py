import unittest
from unittest.mock import patch

from app.ai_comparison import run_model_comparison
from app.database import (
    ai_comparison_detail,
    ai_comparison_scorecard,
    create_ai_comparison_run,
    create_ai_profile,
    delete_ai_profile,
    init_db,
    insert_ai_comparison_candidate,
    list_ai_comparison_runs,
    vote_ai_comparison,
)


class AIComparisonTests(unittest.TestCase):
    def setUp(self):
        self.conn = init_db(":memory:")
        self.profile_uids = []
        for number in range(1, 4):
            self.profile_uids.append(
                create_ai_profile(
                    self.conn,
                    {
                        "name": f"Model {number}",
                        "provider": "ollama",
                        "host": "http://127.0.0.1:11434",
                        "model": f"model-{number}",
                        "status": "active",
                    },
                )
            )

    def tearDown(self):
        self.conn.close()

    def report(self, uid, model):
        return {
            "ai_profile_uid": uid,
            "model_provider": "ollama",
            "model_name": model,
            "model_identity": f"ollama:{model}",
            "model_run_id": f"run-{model}",
            "prompt_version": "test-prompt",
            "prompt_sha256": "same-evidence",
            "classification": "Human Review Required",
            "confidence": "Medium",
            "risk_adjustment": 2,
            "summary": f"Summary from {model}",
            "who": "source and destination",
            "what": "network event",
            "when": "during the case window",
            "where": "network boundary",
            "why": "sensor evidence",
            "how": "correlated metadata",
            "next_steps": ["Validate the named sensor finding."],
            "threat_intel_analysis": {
                "overall": f"Threat intelligence reviewed by {model}",
                "influence": "supports_suspicious",
                "providers": {
                    "otx": "No match",
                    "threatfox": "Matched the destination",
                    "urlhaus": "No match",
                    "sslbl": "No match",
                    "spamhaus_drop": "No match",
                    "openphish": "No match",
                    "ipsum": "No match",
                    "feodo": "No match",
                    "virustotal": "Not requested",
                },
            },
            "recommended_action": "human_review",
            "raw_response": "{}",
            "elapsed_ms": 100,
        }

    def test_all_model_responses_are_visible_before_single_selection(self):
        run_id, comparison_uid = create_ai_comparison_run(
            self.conn, "CASE-TEST", 1, "same-evidence", "test-prompt"
        )
        for slot, uid, model in zip(("A", "B", "C"), self.profile_uids, ("one", "two", "three")):
            insert_ai_comparison_candidate(
                self.conn, run_id, slot, uid, report=self.report(uid, model)
            )

        detail = ai_comparison_detail(self.conn, comparison_uid)
        self.assertTrue(detail["identities_revealed"])
        self.assertEqual(detail["candidates"][0]["model_identity"], "ollama:one")
        self.assertEqual(detail["candidates"][0]["raw_response"], "{}")
        self.assertEqual(detail["candidates"][0]["next_steps"], ["Validate the named sensor finding."])
        self.assertEqual(
            detail["candidates"][0]["threat_intel_analysis"]["providers"]["threatfox"],
            "Matched the destination",
        )

        self.assertTrue(vote_ai_comparison(self.conn, comparison_uid, "analyst", "B", "Best next steps"))
        reviewed = ai_comparison_detail(self.conn, comparison_uid)
        self.assertEqual(reviewed["candidates"][1]["model_identity"], "ollama:two")
        self.assertEqual(ai_comparison_scorecard(self.conn)["models"][0]["ai_profile_uid"], self.profile_uids[1])
        with self.assertRaisesRegex(ValueError, "already been reviewed"):
            vote_ai_comparison(self.conn, comparison_uid, "second analyst", "A")

    def test_deleting_profile_preserves_historical_comparison_response(self):
        run_id, comparison_uid = create_ai_comparison_run(
            self.conn, "CASE-DELETE", 1, "same-evidence", "test-prompt"
        )
        uid = self.profile_uids[0]
        insert_ai_comparison_candidate(
            self.conn, run_id, "A", uid, report=self.report(uid, "one")
        )

        self.assertTrue(delete_ai_profile(self.conn, uid))
        detail = ai_comparison_detail(self.conn, comparison_uid)
        self.assertEqual(detail["candidates"][0]["ai_profile_uid"], uid)
        self.assertEqual(detail["candidates"][0]["model_identity"], "ollama:one")

    @patch("app.ai_comparison.prepare_case_context")
    @patch("app.ai_comparison.ask_ai_model")
    def test_three_requests_run_and_share_one_prompt_evidence(self, mock_ask, mock_prepare):
        workspace = {"detection_id": 1, "case_uid": "CASE-TEST"}
        alert = {
            "timestamp": "2026-07-17T12:00:00+00:00",
            "src_ip": "192.168.11.50",
            "dest_ip": "203.0.113.10",
            "signature": "Test finding",
        }
        detection = {
            "case_uid": "CASE-TEST",
            "detection_type": "unknown",
            "python_initial_score": 30,
        }
        evidence = {
            "sensor_fusion": {"findings": [{"sensor": "suricata"}]},
            "threat_intel": {
                "provider_status": [{"name": "threatfox", "enabled": True}],
                "dest_ip": {"indicator": "203.0.113.10", "providers": []},
            },
        }
        mock_prepare.return_value = (workspace, alert, detection, evidence, {}, [])

        def answer(config, _alert, _detection, evidence_context=None):
            uid = config["ai_model"]["active_profile_uid"]
            model = config["ai_model"]["model"]
            self.assertIs(evidence_context, evidence)
            return self.report(uid, model)

        mock_ask.side_effect = answer
        result = run_model_comparison(
            self.conn,
            {"ai_comparison": {"profile_uids": self.profile_uids}, "ai_model": {}},
            "CASE-TEST",
        )

        self.assertEqual(mock_ask.call_count, 3)
        self.assertEqual(result["candidate_count"], 3)
        self.assertEqual(result["status"], "complete")
        runs = list_ai_comparison_runs(self.conn, case_uid="CASE-TEST")
        self.assertEqual(runs[0]["comparison_uid"], result["comparison_uid"])
        detail = ai_comparison_detail(self.conn, result["comparison_uid"])
        self.assertEqual(
            detail["threat_intel_evidence"]["provider_status"][0]["name"],
            "threatfox",
        )


if __name__ == "__main__":
    unittest.main()

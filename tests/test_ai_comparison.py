import unittest
from unittest.mock import patch

from app.ai_comparison import _comparison_lock, run_model_comparison
from app.database import (
    ai_comparison_detail,
    ai_comparison_export_rows,
    ai_comparison_selection_summary,
    create_ai_comparison_run,
    create_ai_profile,
    delete_ai_profile,
    init_db,
    insert_ai_comparison_candidate,
    list_ai_comparison_runs,
    promote_ai_comparison_winner,
    reopen_ai_comparison_review,
    selected_case_explanation,
    upsert_ai_run_audit,
    vote_ai_comparison,
)
from app.ai_client import (
    build_prompt_audit,
    rebuild_prompt_audit,
    summarize_sensor_findings_for_model,
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
            "classification": "Analyst Review Required",
            "confidence": "Medium",
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
        self.assertFalse(detail["identities_revealed"])
        self.assertIsNone(detail["candidates"][0]["model_identity"])
        self.assertEqual(detail["candidates"][0]["raw_response"], "{}")
        self.assertEqual(detail["candidates"][0]["next_steps"], ["Validate the named sensor finding."])
        self.assertEqual(
            detail["candidates"][0]["threat_intel_analysis"]["providers"]["threatfox"],
            "Matched the destination",
        )

        self.assertTrue(vote_ai_comparison(self.conn, comparison_uid, "analyst", "B", "Best next steps"))
        reviewed = ai_comparison_detail(self.conn, comparison_uid)
        self.assertTrue(reviewed["identities_revealed"])
        self.assertEqual(reviewed["candidates"][1]["model_identity"], "ollama:two")
        self.assertEqual(
            ai_comparison_selection_summary(self.conn)["models"][0]["ai_profile_uid"],
            self.profile_uids[1],
        )
        with self.assertRaisesRegex(ValueError, "already been reviewed"):
            vote_ai_comparison(self.conn, comparison_uid, "second analyst", "A")

    def test_repeated_findings_are_grouped_for_model_without_mutating_source(self):
        findings = [
            {
                "sensor": "suricata",
                "sensor_event_id": number,
                "event_uid": f"SUR-{number}",
                "finding_type": "alert",
                "finding_name": "Repeated DNS signature",
                "source_ip": "192.168.11.50",
                "destination_ip": "8.8.8.8",
                "destination_port": 53,
                "protocol": "udp",
                "timestamp": f"2026-07-27T12:00:{number:02d}+00:00",
                "raw_record_sha256": f"hash-{number}",
            }
            for number in range(10)
        ]
        evidence = {"sensor_fusion": {"findings": findings}}

        summarized = summarize_sensor_findings_for_model(evidence)

        self.assertEqual(len(evidence["sensor_fusion"]["findings"]), 10)
        self.assertEqual(len(summarized["sensor_fusion"]["findings"]), 1)
        representative = summarized["sensor_fusion"]["findings"][0]
        self.assertEqual(representative["occurrence_count"], 10)
        self.assertEqual(len(representative["event_uid_examples"]), 5)
        self.assertEqual(
            summarized["sensor_fusion"]["finding_summary"]["raw_finding_count"],
            10,
        )

    def test_review_can_be_reopened_and_export_reveals_selected_model(self):
        run_id, comparison_uid = create_ai_comparison_run(
            self.conn, "CASE-REOPEN", 1, "same-evidence", "test-prompt"
        )
        for slot, uid, model in zip(
            ("A", "B", "C"), self.profile_uids, ("one", "two", "three")
        ):
            insert_ai_comparison_candidate(
                self.conn, run_id, slot, uid, report=self.report(uid, model)
            )
        vote_ai_comparison(self.conn, comparison_uid, "analyst", "B", "Most useful")

        detail = ai_comparison_detail(self.conn, comparison_uid)
        self.assertEqual(detail["review_outcome"]["status"], "winner_selected")
        self.assertEqual(
            detail["review_outcome"]["winner"]["model_identity"],
            "ollama:two",
        )
        exported = ai_comparison_export_rows(self.conn)
        self.assertEqual(exported[0]["case_uid"], "CASE-REOPEN")
        self.assertEqual(exported[0]["review_status"], "reviewed")
        self.assertEqual(exported[0]["selected_model_identity"], "ollama:two")
        self.assertEqual(exported[0]["response_a_elapsed_ms"], 100)
        self.assertEqual(exported[0]["response_a_elapsed_seconds"], 0.1)
        self.assertEqual(exported[0]["selected_response_elapsed_ms"], 100)
        self.assertEqual(exported[0]["selected_response_elapsed_seconds"], 0.1)
        self.assertEqual(exported[0]["successful_response_total_elapsed_ms"], 300)
        self.assertEqual(
            exported[0]["successful_response_average_elapsed_seconds"],
            0.1,
        )

        self.assertTrue(reopen_ai_comparison_review(self.conn, comparison_uid))
        reopened = ai_comparison_detail(self.conn, comparison_uid)
        self.assertEqual(reopened["review_outcome"]["status"], "awaiting_review")
        summary = ai_comparison_selection_summary(self.conn)
        self.assertEqual(summary["votes"], 0)
        self.assertEqual(summary["reopened_reviews"], 1)

    def test_reviewed_winner_can_be_used_as_case_explanation(self):
        timestamp = "2026-07-27T12:00:00+00:00"
        self.conn.execute(
            """
            INSERT INTO detections (
              id, case_uid, first_seen, last_seen, detection_type
            ) VALUES (1, 'CASE-PROMOTE', ?, ?, 'unknown')
            """,
            (timestamp, timestamp),
        )
        self.conn.commit()
        run_id, comparison_uid = create_ai_comparison_run(
            self.conn, "CASE-PROMOTE", 1, "same-evidence", "test-prompt"
        )
        for slot, uid, model in zip(
            ("A", "B", "C"), self.profile_uids, ("one", "two", "three")
        ):
            insert_ai_comparison_candidate(
                self.conn, run_id, slot, uid, report=self.report(uid, model)
            )

        with self.assertRaisesRegex(ValueError, "Select a comparison winner"):
            promote_ai_comparison_winner(self.conn, comparison_uid)

        vote_ai_comparison(
            self.conn, comparison_uid, "analyst", "C", "Most useful explanation"
        )
        self.assertTrue(
            promote_ai_comparison_winner(
                self.conn,
                comparison_uid,
                "analyst",
                "Use this explanation on the case",
            )
        )

        selected = selected_case_explanation(self.conn, 1)
        self.assertEqual(selected["anonymous_slot"], "C")
        self.assertEqual(selected["model_identity"], "ollama:three")
        self.assertEqual(selected["summary"], "Summary from three")
        self.assertEqual(
            selected["next_steps"],
            ["Validate the named sensor finding."],
        )
        detail = ai_comparison_detail(self.conn, comparison_uid)
        self.assertEqual(
            detail["active_case_explanation"]["comparison_uid"],
            comparison_uid,
        )
        self.assertEqual(
            detail["case_explanation_promotion"]["anonymous_slot"],
            "C",
        )

    def test_rejected_comparisons_are_labeled_for_queue_and_statistics(self):
        run_id, comparison_uid = create_ai_comparison_run(
            self.conn, "CASE-REJECT", 1, "same-evidence", "test-prompt"
        )
        insert_ai_comparison_candidate(
            self.conn,
            run_id,
            "A",
            self.profile_uids[0],
            report=self.report(self.profile_uids[0], "one"),
        )
        vote_ai_comparison(self.conn, comparison_uid, "analyst", "reject_all")

        queue = list_ai_comparison_runs(self.conn)
        self.assertEqual(queue[0]["selection"], "reject_all")
        summary = ai_comparison_selection_summary(self.conn)
        self.assertEqual(summary["rejected"], 1)
        self.assertEqual(summary["reviewed_cases"], 1)

    def test_deleting_profile_preserves_historical_comparison_response(self):
        run_id, comparison_uid = create_ai_comparison_run(
            self.conn, "CASE-DELETE", 1, "same-evidence", "test-prompt"
        )
        uid = self.profile_uids[0]
        insert_ai_comparison_candidate(
            self.conn, run_id, "A", uid, report=self.report(uid, "one")
        )

        self.assertTrue(delete_ai_profile(self.conn, uid))
        self.assertTrue(
            vote_ai_comparison(self.conn, comparison_uid, "analyst", "A", "History")
        )
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
        }
        evidence = {
            "sensor_fusion": {"findings": [{"sensor": "suricata"}]},
            "threat_intel": {
                "provider_status": [{"name": "threatfox", "enabled": True}],
                "dest_ip": {"indicator": "203.0.113.10", "providers": []},
            },
        }
        mock_prepare.return_value = (workspace, alert, detection, evidence, [])

        live_progress = []

        def answer(
            config,
            _alert,
            _detection,
            evidence_context=None,
            progress_callback=None,
            prepared_request=None,
        ):
            runs = list_ai_comparison_runs(self.conn, case_uid="CASE-TEST")
            live_progress.append(
                (runs[0]["candidate_count"], runs[0]["processed_count"])
            )
            uid = config["ai_model"]["active_profile_uid"]
            model = config["ai_model"]["model"]
            self.assertEqual(config["ai_model"]["temperature"], 0.0)
            self.assertEqual(config["ai_model"]["seed"], 42)
            prepared_evidence = prepared_request["evidence_package"]["evidence_context"]
            self.assertEqual(
                prepared_evidence["sensor_fusion"]["findings"][0]["sensor"],
                evidence["sensor_fusion"]["findings"][0]["sensor"],
            )
            self.assertEqual(
                prepared_evidence["threat_intel"],
                evidence["threat_intel"],
            )
            self.assertIsNotNone(progress_callback)
            return self.report(uid, model)

        mock_ask.side_effect = answer
        result = run_model_comparison(
            self.conn,
            {"ai_comparison": {"profile_uids": self.profile_uids}, "ai_model": {}},
            "CASE-TEST",
        )

        self.assertEqual(mock_ask.call_count, 3)
        self.assertEqual([processed for _complete, processed in live_progress], [0, 1, 2])
        self.assertEqual(result["candidate_count"], 3)
        self.assertEqual(result["status"], "complete")
        runs = list_ai_comparison_runs(self.conn, case_uid="CASE-TEST")
        self.assertEqual(runs[0]["comparison_uid"], result["comparison_uid"])
        detail = ai_comparison_detail(self.conn, result["comparison_uid"])
        self.assertEqual(
            detail["threat_intel_evidence"]["provider_status"][0]["name"],
            "threatfox",
        )
        self.assertEqual(detail["processed_count"], 3)

    @patch("app.ai_comparison.prepare_case_context")
    @patch("app.ai_comparison.ask_ai_model")
    def test_comparison_reuses_initial_audited_prompt_snapshot(self, mock_ask, mock_prepare):
        timestamp = "2026-07-17T12:00:00+00:00"
        self.conn.execute(
            """
            INSERT INTO detections (
              id, case_uid, first_seen, last_seen, detection_type
            ) VALUES (1, 'CASE-SNAPSHOT', ?, ?, 'unknown')
            """,
            (timestamp, timestamp),
        )
        self.conn.commit()
        workspace = {"detection_id": 1, "case_uid": "CASE-SNAPSHOT"}
        alert = {
            "timestamp": timestamp,
            "src_ip": "192.168.11.50",
            "dest_ip": "203.0.113.10",
            "signature": "Snapshot finding",
        }
        detection = {
            "case_uid": "CASE-SNAPSHOT",
            "detection_type": "unknown",
        }
        evidence = {"sensor_fusion": {"findings": [{"sensor": "suricata"}]}}
        mock_prepare.return_value = (workspace, alert, detection, evidence, [])
        _prompt, audit = build_prompt_audit(
            {"ai_model": {"host": "http://127.0.0.1:11434", "model": "initial"}},
            alert,
            detection,
            evidence,
        )
        audit.update(
            audit_status="complete",
            raw_response="{}",
            audit_parse_status="valid_json",
        )
        upsert_ai_run_audit(self.conn, 1, audit, assessment_type="initial")

        def answer(
            config,
            _alert,
            _detection,
            evidence_context=None,
            progress_callback=None,
            prepared_request=None,
        ):
            self.assertEqual(prepared_request["prompt_text"], audit["audit_prompt_text"])
            self.assertEqual(
                prepared_request["evidence_sha256"],
                audit["audit_evidence_sha256"],
            )
            _prepared_prompt, request_audit = rebuild_prompt_audit(
                config,
                alert,
                prepared_request,
            )
            report = self.report(
                config["ai_model"]["active_profile_uid"],
                config["ai_model"]["model"],
            )
            report.update(request_audit)
            report.update(
                audit_status="complete",
                audit_parse_status="valid_json",
                audit_response_sha256="response-hash",
            )
            return report

        mock_ask.side_effect = answer
        result = run_model_comparison(
            self.conn,
            {"ai_comparison": {"profile_uids": self.profile_uids}, "ai_model": {}},
            "CASE-SNAPSHOT",
        )

        self.assertEqual(mock_ask.call_count, 3)
        detail = ai_comparison_detail(self.conn, result["comparison_uid"])
        proof = detail["input_consistency"]
        self.assertTrue(proof["same_prompt_across_candidates"])
        self.assertTrue(proof["same_evidence_across_candidates"])
        self.assertTrue(proof["same_generation_options_across_candidates"])
        self.assertTrue(proof["matches_initial_case_prompt"])
        self.assertTrue(proof["matches_initial_case_evidence"])
        exported = next(
            row
            for row in ai_comparison_export_rows(self.conn)
            if row["comparison_uid"] == result["comparison_uid"]
        )
        self.assertEqual(exported["initial_prompt_sha256"], audit["prompt_sha256"])
        self.assertEqual(
            exported["initial_evidence_sha256"],
            audit["audit_evidence_sha256"],
        )
        self.assertEqual(
            exported["response_r01_evidence_sha256"],
            audit["audit_evidence_sha256"],
        )
        self.assertTrue(exported["same_prompt_across_candidates"])
        self.assertTrue(exported["same_evidence_across_candidates"])
        self.assertTrue(exported["matches_initial_prompt"])
        self.assertTrue(exported["matches_initial_evidence"])
        self.assertEqual(
            exported["comparison_run_hash_type"],
            "evidence_package_sha256",
        )

    @patch("app.ai_comparison.prepare_case_context")
    @patch("app.ai_comparison.ask_ai_model")
    def test_failed_candidate_retains_profile_provenance(self, mock_ask, mock_prepare):
        workspace = {"detection_id": 1, "case_uid": "CASE-FAILURE"}
        alert = {"timestamp": "2026-07-17T12:00:00+00:00", "signature": "Test"}
        detection = {"case_uid": "CASE-FAILURE", "detection_type": "unknown"}
        evidence = {"sensor_fusion": {"findings": []}, "threat_intel": {}}
        mock_prepare.return_value = (workspace, alert, detection, evidence, [])

        def answer(
            config,
            _alert,
            _detection,
            evidence_context=None,
            progress_callback=None,
            prepared_request=None,
        ):
            self.assertIsNotNone(progress_callback)
            if config["ai_model"]["model"] == "model-2":
                raise RuntimeError("timed out")
            return self.report(
                config["ai_model"]["active_profile_uid"],
                config["ai_model"]["model"],
            )

        mock_ask.side_effect = answer
        result = run_model_comparison(
            self.conn,
            {"ai_comparison": {"profile_uids": self.profile_uids}, "ai_model": {}},
            "CASE-FAILURE",
        )
        detail = ai_comparison_detail(self.conn, result["comparison_uid"])

        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["candidate_count"], 2)
        self.assertEqual(detail["processed_count"], 3)
        self.assertEqual(detail["candidates"][1]["status"], "failed")
        self.assertEqual(detail["candidates"][1]["ai_profile_uid"], self.profile_uids[1])
        self.assertIsNone(detail["candidates"][1]["model_identity"])
        self.assertEqual(detail["candidates"][1]["error_message"], "timed out")

    def test_process_local_lock_is_not_queue_state(self):
        self.assertTrue(_comparison_lock.acquire(blocking=False))
        try:
            self.assertTrue(_comparison_lock.locked())
        finally:
            _comparison_lock.release()


if __name__ == "__main__":
    unittest.main()

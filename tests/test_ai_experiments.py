import json
import os
import tempfile
import unittest
from unittest.mock import patch

from app.ai_comparison import (
    _variant_prompt,
    anonymous_label,
    mask_evidence_package,
    queue_stability_experiment,
)
from app.database import (
    ai_comparison_candidate_export_rows,
    ai_experiment_export_rows,
    claim_next_ai_experiment_task,
    create_ai_comparison_run,
    create_ai_experiment_run,
    finish_ai_experiment_result,
    init_db,
    insert_ai_comparison_candidate,
    vote_ai_comparison,
)


class AIExperimentTests(unittest.TestCase):
    def setUp(self):
        handle, self.path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        self.conn = init_db(self.path)
        self.conn.execute(
            """
            INSERT INTO detections (id, case_uid, first_seen, last_seen, detection_type)
            VALUES (1, 'CASE-EXPERIMENT', '2026-01-01', '2026-01-01', 'unknown')
            """
        )
        self.conn.execute(
            """
            INSERT INTO ai_profiles
              (uid, name, provider, host, model, timeout_seconds, status)
            VALUES ('ai-test', 'Test', 'ollama', 'http://localhost:11434',
                    'test-model', 90, 'active')
            """
        )
        self.run_id, self.comparison_uid = create_ai_comparison_run(
            self.conn,
            "CASE-EXPERIMENT",
            1,
            "evidence-hash",
            "prompt-v1",
            selected_profile_uids=["ai-test"],
            control_snapshot={
                "prompt_text": "prompt",
                "prompt_sha256": "prompt-hash",
                "evidence_package": {"event_context": {"src_ip": "192.0.2.1"}},
            },
            status="complete",
        )
        self.conn.execute(
            """
            INSERT INTO ai_comparison_candidates (
              comparison_run_id, anonymous_slot, ai_profile_uid, status,
              prompt_sha256, evidence_sha256, response_sha256
            ) VALUES (?, 'R01', 'ai-test', 'complete', 'prompt-hash',
                      'evidence-hash', 'response-hash')
            """,
            (self.run_id,),
        )
        self.candidate_id = self.conn.execute(
            "SELECT id FROM ai_comparison_candidates"
        ).fetchone()["id"]
        self.conn.commit()

    def tearDown(self):
        self.conn.close()
        os.remove(self.path)

    def test_dynamic_labels_support_more_than_five_models(self):
        self.assertEqual(
            [anonymous_label(index) for index in range(7)],
            ["R01", "R02", "R03", "R04", "R05", "R06", "R07"],
        )

    def test_worker_claims_one_task_once(self):
        experiment_uid = create_ai_experiment_run(
            self.conn,
            "sampling_stability",
            self.comparison_uid,
            "CASE-EXPERIMENT",
            1,
            {"settings": [{"temperature": 0.2, "seed": 42}]},
            [
                {
                    "baseline_candidate_id": self.candidate_id,
                    "ai_profile_uid": "ai-test",
                    "anonymous_label": "R01",
                    "variant_label": "Low variation",
                    "temperature": 0.2,
                    "seed": 42,
                }
            ],
        )
        first = claim_next_ai_experiment_task(self.conn)
        second = claim_next_ai_experiment_task(self.conn)
        self.assertEqual(first["experiment_uid"], experiment_uid)
        self.assertIsNone(second)

    def test_stability_experiment_uses_only_selected_response(self):
        self.conn.execute(
            """
            INSERT INTO ai_profiles
              (uid, name, provider, host, model, timeout_seconds, status)
            VALUES ('ai-test-2', 'Test 2', 'ollama', 'http://localhost:11434',
                    'test-model-2', 90, 'active')
            """
        )
        self.conn.commit()
        insert_ai_comparison_candidate(
            self.conn,
            self.run_id,
            "R02",
            "ai-test-2",
            report={
                "model_identity": "ollama:test-model-2",
                "prompt_sha256": "prompt-hash",
                "audit_evidence_sha256": "evidence-hash",
                "audit_response_sha256": "response-hash-2",
                "classification": "Analyst Review Required",
                "confidence": "Medium",
            },
        )
        vote_ai_comparison(
            self.conn, self.comparison_uid, "analyst", "R02", "Selected control"
        )
        settings = [
            {"label": "Low variation", "temperature": 0.2, "seed": 42},
            {"label": "High variation", "temperature": 0.7, "seed": 7},
        ]
        inventory = {
            "digest": None,
            "size": None,
            "quantization": None,
        }
        with patch("app.ai_comparison._verify_current_digest", return_value=inventory):
            experiment_uid = queue_stability_experiment(
                self.conn, {}, self.comparison_uid, settings
            )
        rows = self.conn.execute(
            """
            SELECT results.anonymous_label, results.baseline_candidate_id
            FROM ai_experiment_results AS results
            JOIN ai_experiment_runs AS runs ON runs.id = results.experiment_run_id
            WHERE runs.experiment_uid = ?
            ORDER BY results.id
            """,
            (experiment_uid,),
        ).fetchall()
        selected_id = self.conn.execute(
            """
            SELECT id FROM ai_comparison_candidates
            WHERE comparison_run_id = ? AND anonymous_slot = 'R02'
            """,
            (self.run_id,),
        ).fetchone()["id"]
        self.assertEqual(len(rows), 2)
        self.assertEqual({row["anonymous_label"] for row in rows}, {"R02"})
        self.assertEqual({row["baseline_candidate_id"] for row in rows}, {selected_id})

    def test_masking_removes_ip_zeek_and_threat_intelligence(self):
        package = {
            "event_context": {"src_ip": "192.0.2.1", "dest_ip": "198.51.100.2"},
            "evidence_context": {
                "zeek_context": {"items": [{"sensor": "zeek", "src_ip": "192.0.2.1"}]},
                "sensor_fusion": {
                    "findings": [
                        {"sensor": "zeek", "src_ip": "192.0.2.1"},
                        {"sensor": "suricata", "src_ip": "192.0.2.1"},
                    ]
                },
                "threat_intel": {"src_ip": {"indicator": "192.0.2.1"}},
            },
        }
        masked = mask_evidence_package(
            package, ["source_ip", "zeek_context", "threat_intelligence"]
        )
        text = json.dumps(masked).lower()
        self.assertNotIn("192.0.2.1", text)
        self.assertNotIn('"sensor": "zeek"', text)
        self.assertIn("not_provided_for_experiment", text)
        self.assertEqual(package["event_context"]["src_ip"], "192.0.2.1")

    def test_variant_prompt_accepts_different_json_key_order(self):
        control_package = {
            "event_context": {"src_ip": "192.0.2.1"},
            "correlation": {"status": "matched"},
        }
        prompt = (
            "Instructions\nAnalyze this event package:\n"
            '{"event_context":{"src_ip":"192.0.2.1"},'
            '"correlation":{"status":"matched"}}'
            "\nReturn only JSON"
        )
        # Simulate SQLite loading a canonicalized object with a different key order.
        stored_package = json.loads(
            json.dumps(control_package, sort_keys=True, separators=(",", ":"))
        )
        variant = {
            "correlation": {"status": "not_provided_for_experiment"},
            "event_context": {"src_ip": "192.0.2.1"},
        }
        result = _variant_prompt(prompt, stored_package, variant)
        self.assertIn('"status":"not_provided_for_experiment"', result)
        self.assertNotIn('"status":"matched"', result)

    def test_export_links_control_and_experimental_hashes(self):
        experiment_uid = create_ai_experiment_run(
            self.conn,
            "sampling_stability",
            self.comparison_uid,
            "CASE-EXPERIMENT",
            1,
            {},
            [
                {
                    "baseline_candidate_id": self.candidate_id,
                    "ai_profile_uid": "ai-test",
                    "anonymous_label": "R01",
                    "variant_label": "Trial",
                    "temperature": 0.7,
                    "seed": 7,
                    "parent_prompt_sha256": "prompt-hash",
                    "parent_evidence_sha256": "evidence-hash",
                    "parent_response_sha256": "response-hash",
                }
            ],
        )
        task = claim_next_ai_experiment_task(self.conn)
        finish_ai_experiment_result(
            self.conn,
            task["id"],
            report={
                "prompt_sha256": "prompt-hash",
                "audit_evidence_sha256": "evidence-hash",
                "audit_response_sha256": "variant-response",
                "classification": "Analyst Review Required",
                "confidence": "Medium",
                "summary": "Controlled result",
                "next_steps": ["Review evidence"],
            },
        )
        row = next(
            item
            for item in ai_experiment_export_rows(self.conn)
            if item["experiment_uid"] == experiment_uid
        )
        self.assertEqual(row["parent_prompt_sha256"], "prompt-hash")
        self.assertEqual(row["prompt_sha256"], "prompt-hash")
        self.assertEqual(row["baseline_classification"], None)
        self.assertEqual(row["response_sha256"], "variant-response")

    def test_baseline_export_uses_one_row_per_dynamic_candidate(self):
        self.conn.execute(
            """
            INSERT INTO ai_profiles
              (uid, name, provider, host, model, timeout_seconds, status)
            VALUES ('ai-test-2', 'Test 2', 'ollama', 'http://localhost:11434',
                    'test-model-2', 90, 'active')
            """
        )
        self.conn.commit()
        insert_ai_comparison_candidate(
            self.conn,
            self.run_id,
            "R02",
            "ai-test-2",
            report={
                "model_provider": "ollama",
                "model_name": "test-model",
                "model_identity": "ollama:test-model",
                "model_digest": "full-digest",
                "model_quantization": "Q4_K_M",
                "prompt_sha256": "prompt-hash",
                "audit_evidence_sha256": "evidence-hash",
                "audit_response_sha256": "second-response",
                "classification": "Analyst Review Required",
                "confidence": "Medium",
                "audit_request_options": {
                    "options": {
                        "temperature": 0.0,
                        "seed": 42,
                        "num_ctx": 8192,
                        "num_predict": 1024,
                    }
                },
                "audit_response_metrics": {
                    "prompt_eval_count": 100,
                    "eval_count": 20,
                },
            },
        )
        rows = [
            row
            for row in ai_comparison_candidate_export_rows(self.conn)
            if row["comparison_uid"] == self.comparison_uid
        ]
        self.assertEqual(
            [row["response_label"] for row in rows],
            ["R01", "R02"],
        )
        self.assertEqual(rows[1]["num_ctx"], 8192)
        self.assertEqual(rows[1]["prompt_token_count"], 100)


if __name__ == "__main__":
    unittest.main()

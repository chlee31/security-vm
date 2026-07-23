import tempfile
import unittest
from pathlib import Path

from app.database import (
    create_evaluation_scenario,
    create_evaluation_scoring_run,
    delete_evaluation_case_link,
    delete_evaluation_event_label,
    delete_evaluation_model_review,
    delete_evaluation_scenario,
    delete_evaluation_scoring_run,
    evaluation_export_bundle,
    evaluation_overview,
    get_evaluation_scenario,
    init_db,
    list_evaluation_model_reviews,
    list_evaluation_scoring_runs,
    list_evaluation_scenarios,
    update_evaluation_scenario,
    upsert_evaluation_case_link,
    upsert_evaluation_event_label,
    upsert_evaluation_model_review,
)
from app.evaluation import (
    evaluation_bundle_csv,
    normalize_case_link,
    normalize_event_label,
    normalize_scenario,
)


class EvaluationLabTests(unittest.TestCase):
    def setUp(self):
        self.conn = init_db(":memory:")
        self.conn.execute(
            """
            INSERT INTO alerts (
              event_uid, timestamp, src_ip, dest_ip, signature, severity
            ) VALUES (
              'SUR-20260725-000001', '2026-07-25T14:30:00+00:00',
              '192.168.57.40', '192.168.57.25', 'Controlled test', 2
            )
            """
        )
        self.conn.execute(
            """
            INSERT INTO detections (
              case_uid, first_alert_id, first_seen, last_seen, src_ip, dest_ip,
              detection_type, sensor_state
            ) VALUES (
              'CASE-20260725-000001', 1, '2026-07-25T14:30:00+00:00',
              '2026-07-25T14:32:00+00:00', '192.168.57.40',
              '192.168.57.25', 'port_scan', 'both'
            )
            """
        )
        self.conn.execute(
            """
            INSERT INTO zeek_events (
              event_uid, zeek_uid, log_type, timestamp, source_ip,
              destination_ip, raw_json, ingested_at
            ) VALUES (
              'ZEK-20260725-000001', 'C-EVAL', 'notice',
              '2026-07-25T14:30:01+00:00', '192.168.57.40',
              '192.168.57.25', '{}', '2026-07-25T14:30:02+00:00'
            )
            """
        )
        self.conn.commit()
        self.scenario = normalize_scenario(
            {
                "scenario_uid": "cor-001",
                "name": "Community ID cross-sensor correlation",
                "experiment_type": "correlation",
                "ground_truth_class": "Controlled suspicious activity",
                "authorized_activity": True,
                "attack_succeeded": False,
                "source_ip": "192.168.57.40",
                "destination_ip": "192.168.57.25",
                "start_time": "2026-07-25T10:30:00-04:00",
                "end_time": "2026-07-25T10:32:00-04:00",
                "expected_case_count": 1,
                "expected_sensors": ["suricata", "zeek"],
                "notes": "Controlled test",
            }
        )

    def tearDown(self):
        self.conn.close()

    def test_schema_migrates_existing_database_without_touching_case_data(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "legacy.db"
            legacy = init_db(path)
            legacy.execute(
                """
                INSERT INTO detections (case_uid, first_seen, last_seen, detection_type)
                VALUES ('CASE-KEEP', '2026-07-25T00:00:00+00:00',
                        '2026-07-25T00:00:00+00:00', 'unknown')
                """
            )
            legacy.commit()
            legacy.close()

            migrated = init_db(path)
            try:
                tables = {
                    row["name"]
                    for row in migrated.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    ).fetchall()
                }
                self.assertTrue(
                    {
                        "evaluation_scenarios",
                        "evaluation_case_links",
                        "evaluation_event_labels",
                        "evaluation_scoring_runs",
                        "evaluation_model_reviews",
                    }.issubset(tables)
                )
                self.assertIsNotNone(
                    migrated.execute(
                        "SELECT id FROM detections WHERE case_uid = 'CASE-KEEP'"
                    ).fetchone()
                )
            finally:
                migrated.close()

    def test_scenario_crud_and_deletion_preserve_operational_case(self):
        created = create_evaluation_scenario(self.conn, self.scenario)
        self.assertEqual(created["scenario_uid"], "COR-001")
        self.assertEqual(created["expected_sensors"], ["suricata", "zeek"])

        changed = dict(self.scenario)
        changed["name"] = "Updated correlation test"
        updated = update_evaluation_scenario(self.conn, "COR-001", changed)
        self.assertEqual(updated["name"], "Updated correlation test")
        self.assertEqual(len(list_evaluation_scenarios(self.conn)), 1)

        upsert_evaluation_case_link(
            self.conn,
            "COR-001",
            normalize_case_link(
                {
                    "case_uid": "CASE-20260725-000001",
                    "relationship_status": "expected_related",
                    "analyst_confirmed": True,
                }
            ),
        )
        self.assertTrue(delete_evaluation_scenario(self.conn, "COR-001"))
        self.assertIsNone(get_evaluation_scenario(self.conn, "COR-001"))
        self.assertIsNotNone(
            self.conn.execute(
                "SELECT id FROM detections WHERE case_uid = 'CASE-20260725-000001'"
            ).fetchone()
        )

    def test_case_and_event_ground_truth_are_manual_and_exportable(self):
        create_evaluation_scenario(self.conn, self.scenario)
        link = upsert_evaluation_case_link(
            self.conn,
            "COR-001",
            normalize_case_link(
                {
                    "case_uid": "CASE-20260725-000001",
                    "relationship_status": "observed_related",
                    "analyst_confirmed": True,
                    "notes": "Confirmed from lab run",
                }
            ),
        )
        self.assertTrue(link["case_exists"])
        label = upsert_evaluation_event_label(
            self.conn,
            "COR-001",
            normalize_event_label(
                {
                    "event_uid": "SUR-20260725-000001",
                    "event_sensor": "suricata",
                    "actual_case_uid": "CASE-20260725-000001",
                    "label": "expected_correctly_attached",
                }
            ),
        )
        self.assertTrue(label["expected_membership"])
        self.assertTrue(label["actual_membership"])

        bundle = evaluation_export_bundle(self.conn, "COR-001")
        csv_text = evaluation_bundle_csv(bundle)
        self.assertIn("scenario,COR-001", csv_text)
        self.assertIn("case_link,COR-001", csv_text)
        self.assertIn("event_label,COR-001", csv_text)
        self.assertNotIn("api_key", csv_text.lower())

        self.assertTrue(
            delete_evaluation_event_label(
                self.conn, "COR-001", "suricata", "SUR-20260725-000001"
            )
        )
        self.assertTrue(
            delete_evaluation_case_link(
                self.conn, "COR-001", "CASE-20260725-000001"
            )
        )

    def test_scoring_and_model_review_storage_is_evaluation_only(self):
        create_evaluation_scenario(self.conn, self.scenario)
        run_uid = create_evaluation_scoring_run(
            self.conn,
            {
                "scenario_uid": "COR-001",
                "case_uid": "CASE-20260725-000001",
                "evaluation_type": "ablation",
                "baseline_policy": "deterministic-score-v2",
                "experimental_parameters": {"without": "threat_intelligence"},
                "baseline_score": 45,
                "experimental_score": 30,
                "baseline_classification": "Human Review Required",
                "experimental_classification": "Human Review Required",
                "result": {"official_case_modified": False},
            },
        )
        runs = list_evaluation_scoring_runs(self.conn)
        self.assertEqual(runs[0]["score_difference"], -15)
        self.assertEqual(
            runs[0]["experimental_parameters"]["without"], "threat_intelligence"
        )

        review = upsert_evaluation_model_review(
            self.conn,
            {
                "comparison_run_uid": "cmp-test",
                "profile_uid": "ai-test",
                "anonymous_label": "A",
                "grounding_score": 4,
                "completeness_score": 3,
                "next_steps_score": 2,
                "uncertainty_score": 2,
                "usefulness_score": 4,
                "supported_claims": 5,
                "unsupported_claims": 1,
                "reviewer_name": "analyst",
            },
        )
        self.assertEqual(review["grounding_score"], 4)
        self.assertEqual(len(list_evaluation_model_reviews(self.conn)), 1)
        self.assertTrue(delete_evaluation_model_review(self.conn, review["review_uid"]))
        self.assertTrue(delete_evaluation_scoring_run(self.conn, run_uid))

        detection = self.conn.execute(
            "SELECT * FROM detections WHERE case_uid = 'CASE-20260725-000001'"
        ).fetchone()
        self.assertIsNone(detection["python_initial_score"])

    def test_validation_rejects_circular_or_invalid_inputs(self):
        with self.assertRaisesRegex(ValueError, "Scenario UID"):
            normalize_scenario({**self.scenario, "scenario_uid": "bad uid"})
        with self.assertRaisesRegex(ValueError, "End time"):
            normalize_scenario(
                {
                    **self.scenario,
                    "start_time": "2026-07-25T15:00:00+00:00",
                    "end_time": "2026-07-25T14:00:00+00:00",
                }
            )
        with self.assertRaisesRegex(ValueError, "valid IP"):
            normalize_scenario({**self.scenario, "source_ip": "not-an-ip"})
        with self.assertRaisesRegex(ValueError, "Event label"):
            normalize_event_label(
                {
                    "event_uid": "SUR-1",
                    "event_sensor": "suricata",
                    "label": "python_says_related",
                }
            )

    def test_overview_counts_evaluation_records_separately(self):
        create_evaluation_scenario(self.conn, self.scenario)
        overview = evaluation_overview(self.conn)
        self.assertEqual(overview["scenarios"], 1)
        self.assertEqual(overview["case_links"], 0)
        self.assertEqual(overview["experiments"]["correlation"], 1)


if __name__ == "__main__":
    unittest.main()

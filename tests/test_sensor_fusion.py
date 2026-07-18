import json
import unittest

from app.ai_client import build_prompt
from app.database import (
    find_correlated_detection,
    fuse_detection,
    init_db,
    insert_detection,
    insert_sensor_finding,
    insert_zeek_event,
    latest_sensor_alerts,
    sensor_findings_for_detection,
    zeek_context_for_detection,
)
from app.normalizer import normalize_suricata_event
from app.sensor_fusion import zeek_detection
from app.zeek_normalizer import normalize_zeek_record


class SensorFusionTests(unittest.TestCase):
    def setUp(self):
        self.conn = init_db(":memory:")

    def tearDown(self):
        self.conn.close()

    def base_detection(self, **overrides):
        detection = {
            "first_alert_id": None,
            "first_seen": "2026-07-11T12:00:00+00:00",
            "last_seen": "2026-07-11T12:00:00+00:00",
            "src_ip": "192.168.11.50",
            "dest_ip": "203.0.113.10",
            "src_port": 50000,
            "dest_port": 443,
            "protocol": "tcp",
            "community_id": "1:test-community-id",
            "sensor_state": "suricata_only",
            "agreement_state": "single_sensor",
            "correlation_method": "single_sensor",
            "correlation_confidence": 0.5,
            "detection_type": "unknown",
            "alert_count": 1,
            "unique_dest_ports": 1,
            "unique_dest_hosts": 1,
            "time_window_seconds": 60,
            "mitre_id": None,
            "mitre_name": None,
            "python_initial_score": 20,
            "status": "correlated",
        }
        detection.update(overrides)
        return detection

    def test_normalizers_preserve_community_id_and_notice_flow(self):
        suricata = normalize_suricata_event(
            {
                "event_type": "alert",
                "community_id": "1:abc",
                "alert": {"signature": "test", "severity": 2},
            }
        )
        zeek = normalize_zeek_record(
            {
                "ts": 1,
                "uid": "C1",
                "src": "192.168.11.50",
                "dst": "203.0.113.10",
                "p": 443,
                "note": "SSL::Invalid_Server_Cert",
                "msg": "bad certificate",
                "community_id": "1:abc",
            },
            "notice",
        )
        weird = normalize_zeek_record({"ts": 1, "name": "bad_TCP_checksum"}, "weird")

        self.assertEqual(suricata["community_id"], "1:abc")
        self.assertEqual(zeek["source_ip"], "192.168.11.50")
        self.assertEqual(zeek["destination_port"], 443)
        self.assertTrue(zeek["alert_like"])
        self.assertFalse(weird["alert_like"])

    def test_community_id_correlation_fuses_findings_once(self):
        detection_id = insert_detection(self.conn, self.base_detection())
        insert_sensor_finding(
            self.conn,
            detection_id,
            {
                "sensor": "suricata",
                "sensor_event_id": 10,
                "finding_type": "signature_alert",
                "finding_name": "Possible C2",
                "severity": 2,
                "confidence": 0.9,
                "community_id": "1:test-community-id",
                "raw_event": {},
            },
        )
        zeek_event = {
            "timestamp": "2026-07-11T12:00:02+00:00",
            "source_ip": "192.168.11.50",
            "destination_ip": "203.0.113.10",
            "source_port": 50000,
            "destination_port": 443,
            "protocol": "tcp",
            "community_id": "1:test-community-id",
            "detection_type": "unknown",
        }

        match, method, confidence = find_correlated_detection(self.conn, zeek_event, "zeek")
        insert_sensor_finding(
            self.conn,
            match["id"],
            {
                "sensor": "zeek",
                "sensor_event_id": 20,
                "finding_type": "notice",
                "finding_name": "SSL::Invalid_Server_Cert",
                "severity": 3,
                "confidence": 0.65,
                "community_id": "1:test-community-id",
                "raw_event": {},
            },
        )
        fused = fuse_detection(self.conn, match["id"], zeek_event, method, confidence)
        fused_again = fuse_detection(self.conn, match["id"], zeek_event, method, confidence)

        self.assertEqual(method, "community_id")
        self.assertEqual(fused["sensor_state"], "multi_sensor")
        self.assertEqual(fused["python_initial_score"], 20)
        self.assertEqual(fused_again["python_initial_score"], 20)
        self.assertEqual(len(sensor_findings_for_detection(self.conn, detection_id)), 2)

    def test_zeek_notice_can_create_standalone_detection(self):
        alert, detection = zeek_detection(
            {
                "timestamp": "2026-07-11T12:00:00+00:00",
                "source_ip": "192.168.11.50",
                "destination_ip": "203.0.113.10",
                "destination_port": 443,
                "protocol": "tcp",
                "event_name": "SSL::Invalid_Server_Cert",
                "message": "Certificate validation failed",
                "raw_json": {},
            }
        )

        self.assertEqual(alert["sensor_state"], "zeek_only")
        self.assertEqual(detection["sensor_state"], "zeek_only")
        self.assertGreater(detection["python_initial_score"], 0)

    def test_latest_alerts_can_filter_suricata_zeek_and_combined_cases(self):
        suricata_id = insert_detection(
            self.conn, self.base_detection(sensor_state="suricata_only", community_id=None)
        )
        zeek_id = insert_detection(
            self.conn,
            self.base_detection(
                sensor_state="zeek_only",
                community_id=None,
                src_port=50001,
            ),
        )
        combined_id = insert_detection(
            self.conn,
            self.base_detection(
                sensor_state="multi_sensor",
                agreement_state="supporting",
                community_id=None,
                src_port=50002,
            ),
        )
        findings = (
            (suricata_id, "suricata", 101),
            (zeek_id, "zeek", 102),
            (combined_id, "suricata", 103),
            (combined_id, "zeek", 104),
        )
        for detection_id, sensor, event_id in findings:
            insert_sensor_finding(
                self.conn,
                detection_id,
                {
                    "sensor": sensor,
                    "sensor_event_id": event_id,
                    "finding_type": "notice" if sensor == "zeek" else "signature_alert",
                    "finding_name": f"{sensor} finding",
                    "severity": 2,
                    "confidence": 0.8,
                    "raw_event": {},
                },
            )

        suricata_rows = latest_sensor_alerts(self.conn, sensor_filter="suricata")
        zeek_rows = latest_sensor_alerts(self.conn, sensor_filter="zeek")
        both_rows = latest_sensor_alerts(self.conn, sensor_filter="both")

        self.assertEqual(
            {row["detection_id"] for row in suricata_rows},
            {suricata_id, combined_id},
        )
        self.assertEqual(
            {row["detection_id"] for row in zeek_rows},
            {zeek_id, combined_id},
        )
        self.assertEqual(
            [row["detection_id"] for row in both_rows],
            [combined_id],
        )

    def test_prompt_contains_multi_sensor_policy_and_evidence(self):
        alert = {
            "timestamp": "2026-07-11T12:00:00+00:00",
            "src_ip": "192.168.11.50",
            "dest_ip": "203.0.113.10",
            "dest_port": 443,
            "protocol": "tcp",
            "signature": "Possible C2",
            "category": "malware",
        }
        detection = self.base_detection(sensor_state="multi_sensor", agreement_state="supporting")
        evidence = {
            "sensor_fusion": {
                "sensor_state": "multi_sensor",
                "findings": [
                    {"sensor": "suricata", "finding_name": "Possible C2"},
                    {"sensor": "zeek", "finding_name": "SSL::Invalid_Server_Cert"},
                ],
            },
            "zeek_context": {"items": [{"log_type": "ssl", "message": "bad certificate"}]},
        }

        prompt = build_prompt(alert, detection, evidence_context=evidence)

        self.assertIn("unified network detections from Suricata and Zeek", prompt)
        self.assertIn("Absence of a finding from one sensor", prompt)
        self.assertIn('"sensor_state": "multi_sensor"', prompt)
        self.assertIn("SSL::Invalid_Server_Cert", prompt)

    def test_repeated_suricata_scan_joins_developing_case(self):
        detection_id = insert_detection(
            self.conn,
            self.base_detection(
                community_id=None,
                detection_type="port_scan",
                src_port=40000,
                dest_port=22,
            ),
        )
        insert_sensor_finding(
            self.conn,
            detection_id,
            {
                "sensor": "suricata",
                "sensor_event_id": 301,
                "finding_type": "signature_alert",
                "finding_name": "Scan attempt",
                "severity": 2,
                "confidence": 0.8,
                "raw_event": {},
            },
        )
        repeated = {
            "timestamp": "2026-07-11T12:02:00+00:00",
            "src_ip": "192.168.11.50",
            "dest_ip": "203.0.113.20",
            "src_port": 40001,
            "dest_port": 443,
            "protocol": "tcp",
            "signature": "Scan attempt",
            "detection_type": "port_scan",
        }

        match, method, confidence = find_correlated_detection(
            self.conn,
            repeated,
            "suricata",
            same_sensor_window_seconds=300,
        )

        self.assertEqual(match["id"], detection_id)
        self.assertEqual(method, "same_sensor_behavior")
        self.assertEqual(confidence, 0.78)

    def test_shared_tls_name_correlates_related_flows(self):
        detection_id = insert_detection(
            self.conn,
            self.base_detection(
                community_id=None,
                detection_type="unknown",
                dest_port=443,
            ),
        )
        insert_sensor_finding(
            self.conn,
            detection_id,
            {
                "sensor": "suricata",
                "sensor_event_id": 401,
                "finding_type": "signature_alert",
                "finding_name": "Suspicious TLS activity",
                "severity": 2,
                "confidence": 0.8,
                "raw_event": {"tls": {"sni": "example.test"}},
            },
        )
        zeek_notice = {
            "timestamp": "2026-07-11T12:00:20+00:00",
            "source_ip": "192.168.11.50",
            "destination_ip": "203.0.113.10",
            "source_port": 50001,
            "destination_port": 8443,
            "protocol": "tcp",
            "detection_type": "unknown",
            "raw_json": {"server_name": "example.test"},
        }

        match, method, confidence = find_correlated_detection(
            self.conn,
            zeek_notice,
            "zeek",
            tolerance_seconds=10,
            same_sensor_window_seconds=300,
        )

        self.assertEqual(match["id"], detection_id)
        self.assertEqual(method, "shared_observable")
        self.assertEqual(confidence, 0.82)

    def test_zeek_context_is_bounded_and_summarized(self):
        detection_id = insert_detection(
            self.conn,
            self.base_detection(community_id=None, detection_type="beaconing"),
        )
        events = [
            {
                "zeek_uid": f"C{index}",
                "log_type": "conn",
                "timestamp": f"2026-07-11T12:00:0{index}+00:00",
                "source_ip": "192.168.11.50",
                "source_port": 50000 + index,
                "destination_ip": "203.0.113.10",
                "destination_port": 443,
                "protocol": "tcp",
                "event_name": "ssl",
                "message": "TLS connection",
                "raw_json": {"duration": 1.5, "orig_bytes": 100, "resp_bytes": 200},
            }
            for index in range(1, 4)
        ]
        events.append(
            {
                "zeek_uid": "UNRELATED",
                "log_type": "dns",
                "timestamp": "2026-07-11T12:00:02+00:00",
                "source_ip": "192.0.2.55",
                "destination_ip": "192.0.2.53",
                "protocol": "udp",
                "event_name": "A",
                "message": "unrelated.example",
                "raw_json": {"query": "unrelated.example"},
            }
        )
        for event in events:
            insert_zeek_event(self.conn, event)

        context = zeek_context_for_detection(self.conn, detection_id, seconds=30)

        self.assertEqual(context["summary"]["event_count"], 3)
        self.assertEqual(context["summary"]["originator_bytes"], 300)
        self.assertEqual(context["summary"]["responder_bytes"], 600)
        self.assertNotIn("unrelated.example", context["summary"]["dns_queries"])


if __name__ == "__main__":
    unittest.main()

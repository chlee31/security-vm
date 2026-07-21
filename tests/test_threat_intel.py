import unittest
import json
from unittest.mock import patch

from app.config import normalize_legacy_config_keys
from app.database import (
    init_db,
    replace_threat_intel_indicators,
    threat_intel_matches,
    threat_intel_provider_results,
)
from app.threat_intel import (
    ai_provider_status,
    provider_evidence_for_indicator,
    sanitized_provider_status,
    zeek_context_threat_intel,
    zeek_event_observables,
)
from app.main import alert_observables, verify_dangerous_with_virustotal
from app.decision_engine import decide
from app.virustotal import eligible_ip


class ThreatIntelTests(unittest.TestCase):
    def setUp(self):
        self.conn = init_db(":memory:")

    def tearDown(self):
        self.conn.close()

    def test_exact_and_cidr_ip_matches(self):
        replace_threat_intel_indicators(
            self.conn,
            "ipsum",
            [
                {"indicator": "203.0.113.8", "indicator_type": "ip", "confidence": 65},
                {"indicator": "198.51.100.0/24", "indicator_type": "cidr", "confidence": 100},
            ],
        )

        exact = threat_intel_matches(self.conn, "203.0.113.8")
        network = threat_intel_matches(self.conn, "198.51.100.23")

        self.assertEqual(exact[0]["indicator"], "203.0.113.8")
        self.assertEqual(network[0]["indicator"], "198.51.100.0/24")

    def test_disabled_provider_reports_not_active_even_with_cached_match(self):
        replace_threat_intel_indicators(
            self.conn,
            "ipsum",
            [{"indicator": "203.0.113.8", "indicator_type": "ip", "confidence": 65}],
        )
        providers = [{"name": "ipsum", "enabled": False, "label": "IPsum"}]

        result = threat_intel_provider_results(self.conn, "203.0.113.8", providers)[0]

        self.assertEqual(result["result"], "not_active")
        self.assertEqual(result["matches"], [])

    def test_provider_status_requires_key_when_enabled(self):
        config = {
            "threat_intel": {
                "providers": {
                    "threatfox": {"enabled": True, "api_key": "", "refresh_hours": 6}
                }
            }
        }

        statuses = {item["name"]: item for item in sanitized_provider_status(config, self.conn)}

        self.assertEqual(statuses["threatfox"]["status"], "missing_key")

    def test_ai_provider_evidence_lists_every_source_without_credentials(self):
        config = {
            "threat_intel": {
                "providers": {
                    "threatfox": {
                        "enabled": True,
                        "api_key": "must-never-enter-model-evidence",
                        "refresh_hours": 6,
                    }
                }
            }
        }
        providers = ai_provider_status(config, self.conn)
        evidence = provider_evidence_for_indicator(
            self.conn, config, "203.0.113.8", "ip"
        )

        self.assertEqual(len(providers), 9)
        self.assertEqual(len(evidence), 9)
        serialized = json.dumps({"providers": providers, "evidence": evidence})
        self.assertNotIn("must-never-enter-model-evidence", serialized)
        self.assertIn("threatfox", serialized)
        self.assertIn("virustotal", serialized)

    def test_legacy_otx_settings_are_migrated(self):
        config = {
            "threat_intel": {
                "otx_enabled": True,
                "otx_api_key": "saved-key",
            }
        }

        normalized = normalize_legacy_config_keys(config)

        self.assertTrue(normalized["threat_intel"]["providers"]["otx"]["enabled"])
        self.assertEqual(normalized["threat_intel"]["providers"]["otx"]["api_key"], "saved-key")

    def test_suricata_observables_include_dns_tls_http_and_hashes(self):
        alert = {
            "dest_port": 443,
            "raw_json": json.dumps(
                {
                    "dns": {"rrname": "Example.COM"},
                    "tls": {"sni": "c2.example.net", "fingerprint": "AA:BB"},
                    "http": {"hostname": "download.example.org", "url": "/payload"},
                    "fileinfo": {"sha256": "ABC123"},
                }
            ),
        }

        values = {(item["indicator"], item["indicator_type"]) for item in alert_observables(alert)}

        self.assertIn(("example.com", "domain"), values)
        self.assertIn(("c2.example.net", "domain"), values)
        self.assertIn(("https://download.example.org/payload", "url"), values)
        self.assertIn(("aabb", "sha1_certificate"), values)
        self.assertIn(("abc123", "sha256"), values)

    def test_zeek_observables_preserve_log_and_endpoint_provenance(self):
        event = {
            "id": 42,
            "log_type": "dns",
            "timestamp": "2026-07-21T12:00:00+00:00",
            "zeek_uid": "C-test",
            "source_ip": "192.168.11.50",
            "source_port": 53000,
            "destination_ip": "8.8.8.8",
            "destination_port": 53,
            "protocol": "udp",
            "raw_json": json.dumps(
                {"query": "C2.Example.test", "answers": ["203.0.113.9", "alias.example.test"]}
            ),
        }

        observables = zeek_event_observables(event)
        values = {(item["indicator"], item["indicator_type"]) for item in observables}

        self.assertIn(("192.168.11.50", "ip"), values)
        self.assertIn(("8.8.8.8", "ip"), values)
        self.assertIn(("c2.example.test", "domain"), values)
        self.assertIn(("203.0.113.9", "ip"), values)
        query = next(item for item in observables if item["indicator"] == "c2.example.test")
        self.assertEqual(query["provenance"]["log_type"], "dns")
        self.assertEqual(query["provenance"]["zeek_uid"], "C-test")

    def test_zeek_context_matches_cached_intel_and_reports_associated_ips(self):
        replace_threat_intel_indicators(
            self.conn,
            "threatfox",
            [{
                "indicator": "c2.example.test",
                "indicator_type": "domain",
                "category": "botnet_c2",
                "confidence": 90,
            }],
        )
        config = {
            "threat_intel": {
                "providers": {"threatfox": {"enabled": True, "api_key": "configured"}}
            }
        }
        evidence = zeek_context_threat_intel(
            self.conn,
            config,
            [{
                "id": 7,
                "log_type": "ssl",
                "timestamp": "2026-07-21T12:00:00+00:00",
                "source_ip": "192.168.11.50",
                "destination_ip": "203.0.113.9",
                "raw_json": {"server_name": "c2.example.test", "version": "TLSv13"},
            }],
        )

        matched = next(item for item in evidence["items"] if item["indicator"] == "c2.example.test")
        self.assertEqual(evidence["matched_count"], 1)
        self.assertEqual(matched["log_types"], ["ssl"])
        self.assertEqual(matched["associated_ips"], ["192.168.11.50", "203.0.113.9"])
        self.assertEqual(matched["matches"][0]["source"], "threatfox")

    @patch("app.virustotal.lookup_virustotal_ip")
    def test_virustotal_runs_only_after_dangerous_ai_result(self, lookup):
        lookup.return_value = {
            "indicator": "8.8.8.8",
            "indicator_type": "ip",
            "source": "virustotal",
            "reputation": "malicious",
            "malicious_count": 3,
            "suspicious_count": 1,
            "lookup_result": "malicious 3; suspicious 1",
            "raw_response": "{}",
        }
        config = {
            "threat_intel": {
                "cache_ttl_hours": 24,
                "providers": {
                    "virustotal": {"enabled": True, "api_key": "test-key", "refresh_hours": 24}
                },
            }
        }
        alert = {"src_ip": "192.168.11.50", "dest_ip": "8.8.8.8"}

        safe = verify_dangerous_with_virustotal(
            self.conn, config, alert, 10, 20, {"classification": "Safe"}
        )
        dangerous = verify_dangerous_with_virustotal(
            self.conn, config, alert, 10, 20, {"classification": "Dangerous"}
        )

        self.assertEqual(safe[0]["request_state"], "not_requested")
        self.assertEqual(len(dangerous), 1)
        lookup.assert_called_once()
        usage = self.conn.execute(
            "SELECT source, stage FROM threat_intel_usage WHERE detection_id = 10"
        ).fetchone()
        self.assertEqual(dict(usage), {"source": "virustotal", "stage": "post_initial_verification"})

    def test_virustotal_never_changes_the_score(self):
        alert = {"src_ip": "192.168.11.50", "dest_ip": "8.8.8.8"}
        detection = {"python_initial_score": 60}
        base = decide(self.conn, {"system": {"mode": "alert_only"}}, alert, detection, {"risk_adjustment": 4})
        verified = decide(
            self.conn,
            {"system": {"mode": "alert_only"}},
            alert,
            detection,
            {
                "risk_adjustment": 4,
                "virustotal_verification": [{"malicious_count": 50, "suspicious_count": 10}],
            },
        )
        self.assertEqual(base["final_score"], verified["final_score"])

    def test_virustotal_rejects_non_global_and_shared_space(self):
        self.assertFalse(eligible_ip("192.168.11.50"))
        self.assertFalse(eligible_ip("100.99.223.100"))
        self.assertFalse(eligible_ip("127.0.0.1"))
        self.assertTrue(eligible_ip("8.8.8.8"))


if __name__ == "__main__":
    unittest.main()

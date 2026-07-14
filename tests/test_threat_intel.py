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
from app.threat_intel import sanitized_provider_status
from app.main import alert_observables, verify_dangerous_with_virustotal
from app.decision_engine import virustotal_adjustment


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

    @patch("app.main.lookup_virustotal_ip")
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

        self.assertEqual(safe, [])
        self.assertEqual(len(dangerous), 1)
        lookup.assert_called_once()
        usage = self.conn.execute(
            "SELECT source, stage FROM threat_intel_usage WHERE detection_id = 10"
        ).fetchone()
        self.assertEqual(dict(usage), {"source": "virustotal", "stage": "post_ai_verification"})

    def test_virustotal_can_raise_but_not_lower_the_python_score(self):
        self.assertEqual(virustotal_adjustment({"virustotal_verification": []}), 0)
        self.assertEqual(
            virustotal_adjustment(
                {"virustotal_verification": [{"malicious_count": 3, "suspicious_count": 1}]}
            ),
            7,
        )
        self.assertEqual(
            virustotal_adjustment(
                {"virustotal_verification": [{"malicious_count": 0, "suspicious_count": 2}]}
            ),
            3,
        )


if __name__ == "__main__":
    unittest.main()

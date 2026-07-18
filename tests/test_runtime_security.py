import unittest
from unittest.mock import MagicMock, patch

from app.main import run_zeek_ingest
from app.security import redact_secrets


class RuntimeSecurityTests(unittest.TestCase):
    def test_configured_credentials_are_redacted(self):
        config = {
            "threat_intel": {
                "providers": {"otx": {"api_key": "top-secret-key"}},
            }
        }
        result = redact_secrets("request failed api_key=top-secret-key", config)
        self.assertNotIn("top-secret-key", result)
        self.assertIn("***", result)

    @patch("app.main.zeek_status", return_value={"installed": True, "running": True})
    @patch("app.main.init_db")
    @patch("app.main.load_config", return_value={"database": {"path": ":memory:"}, "zeek": {"enabled": False}})
    def test_zeek_ingest_cannot_be_disabled(self, _load_config, init_db, _zeek_status):
        init_db.return_value = MagicMock()
        with self.assertRaisesRegex(RuntimeError, "required"):
            run_zeek_ingest("config.yaml")

    @patch("app.main.zeek_status", return_value={"installed": False, "running": False})
    @patch("app.main.init_db")
    @patch("app.main.load_config", return_value={"database": {"path": ":memory:"}, "zeek": {"enabled": True}})
    def test_zeek_ingest_requires_installed_sensor(self, _load_config, init_db, _zeek_status):
        init_db.return_value = MagicMock()
        with self.assertRaisesRegex(RuntimeError, "required"):
            run_zeek_ingest("config.yaml")


if __name__ == "__main__":
    unittest.main()

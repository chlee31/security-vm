import unittest
from unittest.mock import patch

from app.bootstrap import zeek_os_recommendation, zeek_setup_wizard


class BootstrapOperatingSystemTests(unittest.TestCase):
    def test_ubuntu_2204_and_newer_are_recommended(self):
        for version in ("22.04", "24.04", "26.04"):
            result = zeek_os_recommendation(
                {"id": "ubuntu", "version_id": version, "pretty_name": f"Ubuntu {version}"}
            )
            self.assertTrue(result["recommended"])

    def test_older_or_non_ubuntu_hosts_are_not_recommended(self):
        cases = (("ubuntu", "20.04"), ("debian", "12"), ("unknown", ""))
        for os_id, version in cases:
            result = zeek_os_recommendation(
                {"id": os_id, "version_id": version, "pretty_name": os_id}
            )
            self.assertFalse(result["recommended"])

    @patch("app.bootstrap.resolve_tool_path", return_value="")
    @patch("app.bootstrap.detected_interfaces", return_value=[])
    @patch("app.bootstrap.yes_no")
    def test_zeek_setup_keeps_required_sensor_enabled(self, yes_no, _interfaces, _tool_path):
        def answer(prompt, default=False):
            if prompt == "Enable Zeek?":
                return False
            if prompt == "Use Zeek JSON logs?":
                return True
            return False

        yes_no.side_effect = answer
        config = {"zeek": {"enabled": False}, "assets": {"internal_interface": "ens37"}}

        zeek_setup_wizard(config)

        self.assertTrue(config["zeek"]["enabled"])
        self.assertTrue(config["zeek"]["json_logs"])
        self.assertEqual(config["zeek"]["interface"], "ens37")
        self.assertNotIn("Enable Zeek?", [call.args[0] for call in yes_no.call_args_list])


if __name__ == "__main__":
    unittest.main()

import unittest

from app.bootstrap import zeek_os_recommendation


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


if __name__ == "__main__":
    unittest.main()

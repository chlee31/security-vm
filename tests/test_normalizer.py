import unittest

from app.normalizer import detection_type_from_alert


class DetectionTypeTests(unittest.TestCase):
    def classify(self, signature, category=""):
        return detection_type_from_alert({"signature": signature, "category": category})

    def test_explicit_behavior_patterns_are_classified(self):
        cases = {
            "ET SCAN Nmap Scripting Engine User-Agent Detected": "port_scan",
            "Possible SYN Scan in Progress": "port_scan",
            "ET DYN_DNS DYNAMIC_DNS Query to nip.io Domain": "dns_tunneling",
            "Possible DNS Tunneling Detected": "dns_tunneling",
            "Known C2 Callback Traffic": "beaconing",
            "Repeated SSH Brute Force Attempt": "brute_force",
        }
        for signature, expected in cases.items():
            with self.subTest(signature=signature):
                self.assertEqual(self.classify(signature), expected)

    def test_generic_protocol_words_remain_unknown(self):
        signatures = (
            "ET INFO Observed DNS Query",
            "ET INFO TCP SYN packet",
            "HTTP Login Page Requested",
            "Normal SSH Connection Established",
        )
        for signature in signatures:
            with self.subTest(signature=signature):
                self.assertEqual(self.classify(signature), "unknown")


if __name__ == "__main__":
    unittest.main()

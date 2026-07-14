import unittest

from app.zeek_normalizer import load_zeek_json_line, normalize_zeek_record


class ZeekNormalizerTests(unittest.TestCase):
    def test_notice_json_normalizes(self):
        raw = load_zeek_json_line(
            '{"ts": 1720000000.0, "uid": "C1", "id.orig_h": "192.168.11.50", '
            '"id.orig_p": 51515, "id.resp_h": "8.8.8.8", "id.resp_p": 443, '
            '"proto": "tcp", "note": "Scan::Address_Scan", "msg": "scan detected"}'
        )
        event = normalize_zeek_record(raw, "notice")
        self.assertEqual(event["log_type"], "notice")
        self.assertEqual(event["zeek_uid"], "C1")
        self.assertEqual(event["source_ip"], "192.168.11.50")
        self.assertEqual(event["destination_port"], 443)
        self.assertTrue(event["alert_like"])

    def test_malformed_json_raises_value_error(self):
        with self.assertRaises(ValueError):
            load_zeek_json_line("{bad json")


if __name__ == "__main__":
    unittest.main()

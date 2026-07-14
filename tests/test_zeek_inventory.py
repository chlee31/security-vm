import unittest
from pathlib import Path
from unittest.mock import patch

from app.zeek_inventory import log_file_status


class ZeekInventoryTests(unittest.TestCase):
    def test_missing_log_is_reported_without_error(self):
        status = log_file_status(Path("/definitely/missing/zeek.log"))

        self.assertFalse(status["exists"])
        self.assertTrue(status["accessible"])
        self.assertEqual(status["error"], "")

    def test_permission_error_is_reported_without_raising(self):
        path = Path("/opt/zeek/logs/current/conn.log")
        with patch.object(Path, "stat", side_effect=PermissionError(13, "Permission denied", str(path))):
            status = log_file_status(path)

        self.assertFalse(status["exists"])
        self.assertFalse(status["accessible"])
        self.assertIn("Permission denied", status["error"])


if __name__ == "__main__":
    unittest.main()

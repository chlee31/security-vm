import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.zeek_inventory import log_file_status, running_zeek_pids


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

    def test_running_pid_is_verified_from_proc_without_signal_permission_probe(self):
        process = subprocess.Popen(["bash", "-c", "exec -a zeek sleep 10"])
        try:
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                zeekctl = root / "bin" / "zeekctl"
                pid_file = root / "spool" / "zeek" / ".pid"
                zeekctl.parent.mkdir(parents=True)
                pid_file.parent.mkdir(parents=True)
                zeekctl.touch()
                pid_file.write_text(str(process.pid), encoding="utf-8")

                self.assertEqual(running_zeek_pids(str(zeekctl)), [process.pid])
        finally:
            process.terminate()
            process.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()

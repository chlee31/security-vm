import subprocess
import unittest
from unittest.mock import call, patch

from app.bootstrap import ensure_router_firewall_policy


class RouterSetupTests(unittest.TestCase):
    @patch("app.bootstrap.subprocess.run")
    def test_firewalld_policy_is_created_with_explicit_zone_direction(self, run):
        run.side_effect = [
            subprocess.CompletedProcess([], 0, stdout="allow-host-ipv6\n", stderr=""),
            subprocess.CompletedProcess([], 0),
            subprocess.CompletedProcess([], 1, stdout="no\n", stderr=""),
            subprocess.CompletedProcess([], 0),
            subprocess.CompletedProcess([], 1, stdout="no\n", stderr=""),
            subprocess.CompletedProcess([], 0),
            subprocess.CompletedProcess([], 0),
        ]

        ensure_router_firewall_policy()

        self.assertIn(
            call(
                "sudo firewall-cmd --permanent --new-policy=security-vm-route".split(),
                check=True,
            ),
            run.call_args_list,
        )
        self.assertIn(
            call(
                "sudo firewall-cmd --permanent --policy=security-vm-route --add-ingress-zone=internal".split(),
                check=True,
            ),
            run.call_args_list,
        )
        self.assertIn(
            call(
                "sudo firewall-cmd --permanent --policy=security-vm-route --add-egress-zone=external".split(),
                check=True,
            ),
            run.call_args_list,
        )
        self.assertEqual(
            run.call_args_list[-1],
            call(
                "sudo firewall-cmd --permanent --policy=security-vm-route --set-target=ACCEPT".split(),
                check=True,
            ),
        )


if __name__ == "__main__":
    unittest.main()

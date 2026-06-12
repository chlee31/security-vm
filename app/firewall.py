import subprocess
import time


def temporary_block_firewalld(ip_address, timeout_seconds):
    start = time.monotonic()
    rule = f'rule family="ipv4" source address="{ip_address}" drop'
    command = ["sudo", "firewall-cmd", f"--add-rich-rule={rule}", f"--timeout={timeout_seconds}"]
    try:
        subprocess.run(command, check=True, capture_output=True, text=True)
        status = "blocked"
    except subprocess.CalledProcessError as exc:
        status = f"failed: {exc.stderr.strip()}"
    return status, int((time.monotonic() - start) * 1000)

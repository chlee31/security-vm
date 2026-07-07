import subprocess
import time
import getpass


def run_status_command(command):
    try:
        result = subprocess.run(command, check=False, capture_output=True, text=True, timeout=3)
        return {
            "ok": result.returncode == 0,
            "returncode": result.returncode,
            "stdout": (result.stdout or "").strip(),
            "stderr": (result.stderr or "").strip(),
        }
    except (OSError, subprocess.SubprocessError) as exc:
        return {
            "ok": False,
            "returncode": None,
            "stdout": "",
            "stderr": str(exc),
        }


def firewalld_drop_rule(ip_address, direction="source"):
    if direction == "outbound_destination":
        return f'rule family="ipv4" destination address="{ip_address}" drop'
    return f'rule family="ipv4" source address="{ip_address}" drop'


def firewalld_setup_commands():
    current_user = getpass.getuser()
    return [
        "sudo systemctl enable --now firewalld",
        "sudo firewall-cmd --state",
        "sudo firewall-cmd --reload",
        f"echo '{current_user} ALL=(root) NOPASSWD: /usr/bin/firewall-cmd' | sudo tee /etc/sudoers.d/security-vm-firewall",
        "sudo chmod 440 /etc/sudoers.d/security-vm-firewall",
    ]


def firewalld_runtime_status():
    service = run_status_command(["systemctl", "is-active", "firewalld"])
    state = run_status_command(["sudo", "-n", "firewall-cmd", "--state"])
    rich_rules = run_status_command(["sudo", "-n", "firewall-cmd", "--list-rich-rules"])
    rules = [line for line in rich_rules.get("stdout", "").splitlines() if line.strip()]
    running = state.get("stdout") == "running" or service.get("stdout") == "active"
    errors = []
    for item in (service, state, rich_rules):
        error = item.get("stderr")
        if error and error not in errors:
            errors.append(error)
    return {
        "running": running,
        "service_state": service.get("stdout") or "unknown",
        "firewall_state": state.get("stdout") or "unknown",
        "rich_rules": rules,
        "rule_count": len(rules),
        "errors": errors,
    }


def temporary_block_firewalld(ip_address, timeout_seconds, direction="source"):
    start = time.monotonic()
    rule = firewalld_drop_rule(ip_address, direction)
    command = ["sudo", "-n", "firewall-cmd", f"--add-rich-rule={rule}", f"--timeout={timeout_seconds}"]
    try:
        subprocess.run(command, check=True, capture_output=True, text=True)
        status = "blocked"
    except subprocess.CalledProcessError as exc:
        status = f"failed: {exc.stderr.strip()}"
    return status, int((time.monotonic() - start) * 1000), rule


def remove_firewalld_block(ip_address, direction="source"):
    start = time.monotonic()
    rule = firewalld_drop_rule(ip_address, direction)
    command = ["sudo", "-n", "firewall-cmd", f"--remove-rich-rule={rule}"]
    try:
        subprocess.run(command, check=True, capture_output=True, text=True)
        status = "released"
    except subprocess.CalledProcessError as exc:
        status = f"failed: {exc.stderr.strip()}"
    return status, int((time.monotonic() - start) * 1000), rule

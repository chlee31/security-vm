import subprocess
import time
import ipaddress


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
    return [
        "sudo systemctl enable --now firewalld",
        "sudo firewall-cmd --state",
        "sudo firewall-cmd --get-active-zones",
        "sudo firewall-cmd --zone=external --list-rich-rules",
        "sudo firewall-cmd --zone=internal --list-rich-rules",
    ]


def firewalld_zone(ip_address, direction="source", external_zone="external", internal_zone="internal"):
    if direction == "outbound_destination":
        return internal_zone
    try:
        return internal_zone if ipaddress.ip_address(ip_address).is_private else external_zone
    except ValueError:
        return external_zone


def firewalld_runtime_status(external_zone="external", internal_zone="internal"):
    service = run_status_command(["systemctl", "is-active", "firewalld"])
    state = run_status_command(["sudo", "-n", "firewall-cmd", "--state"])
    zone_results = {
        zone: run_status_command(["sudo", "-n", "firewall-cmd", f"--zone={zone}", "--list-rich-rules"])
        for zone in dict.fromkeys([external_zone, internal_zone])
    }
    rules_by_zone = {
        zone: [line for line in result.get("stdout", "").splitlines() if line.strip()]
        for zone, result in zone_results.items()
    }
    rules = [f"{zone}: {rule}" for zone, values in rules_by_zone.items() for rule in values]
    running = state.get("stdout") == "running" or service.get("stdout") == "active"
    errors = []
    for item in (service, state, *zone_results.values()):
        error = item.get("stderr")
        if error and error not in errors:
            errors.append(error)
    return {
        "running": running,
        "service_state": service.get("stdout") or "unknown",
        "firewall_state": state.get("stdout") or "unknown",
        "rich_rules": rules,
        "rules_by_zone": rules_by_zone,
        "rule_count": len(rules),
        "errors": errors,
    }


def temporary_block_firewalld(
    ip_address,
    timeout_seconds,
    direction="source",
    zone=None,
    external_zone="external",
    internal_zone="internal",
):
    start = time.monotonic()
    rule = firewalld_drop_rule(ip_address, direction)
    zone = zone or firewalld_zone(ip_address, direction, external_zone, internal_zone)
    command = ["sudo", "-n", "firewall-cmd", f"--zone={zone}", f"--add-rich-rule={rule}", f"--timeout={timeout_seconds}"]
    try:
        subprocess.run(command, check=True, capture_output=True, text=True)
        status = "blocked"
    except subprocess.CalledProcessError as exc:
        status = f"failed: {exc.stderr.strip()}"
    return status, int((time.monotonic() - start) * 1000), rule, zone


def remove_firewalld_block(
    ip_address,
    direction="source",
    zone=None,
    external_zone="external",
    internal_zone="internal",
):
    start = time.monotonic()
    rule = firewalld_drop_rule(ip_address, direction)
    zone = zone or firewalld_zone(ip_address, direction, external_zone, internal_zone)
    command = ["sudo", "-n", "firewall-cmd", f"--zone={zone}", f"--remove-rich-rule={rule}"]
    try:
        subprocess.run(command, check=True, capture_output=True, text=True)
        status = "released"
    except subprocess.CalledProcessError as exc:
        status = f"failed: {exc.stderr.strip()}"
    return status, int((time.monotonic() - start) * 1000), rule, zone

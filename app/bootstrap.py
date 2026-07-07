import ipaddress
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import requests
import yaml

from app.config import DEFAULT_CONFIG, save_config
from app.database import init_db


REQUIRED_TOOLS = {
    "iproute2": "ip",
    "netplan": "netplan",
    "tailscale": "tailscale",
    "suricata": "suricata",
    "sqlite3": "sqlite3",
    "wireshark": "wireshark",
    "tshark": "tshark",
    "dumpcap": "dumpcap",
    "firewalld": "firewall-cmd",
}

APT_PACKAGES = {
    "iproute2": "iproute2",
    "netplan": "netplan.io",
    "suricata": "suricata",
    "sqlite3": "sqlite3",
    "wireshark": "wireshark",
    "tshark": "tshark",
    "dumpcap": "tshark",
    "firewalld": "firewalld",
}


def yes_no(prompt, default=False):
    suffix = "Y/n" if default else "y/N"
    answer = input(f"{prompt} [{suffix}]: ").strip().lower()
    if not answer:
        return default
    return answer in {"y", "yes"}


def check_tool(name, binary):
    path = shutil.which(binary)
    status = "installed" if path else "missing"
    print(f"{name:10} {status:10} {path or ''}")
    return bool(path)


def run_json(command):
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        return json.loads(result.stdout or "[]")
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError):
        return []


def detected_interfaces():
    rows = run_json(["ip", "-j", "addr", "show"])
    interfaces = []
    for row in rows:
        name = row.get("ifname", "")
        if not name or name == "lo":
            continue
        addresses = []
        for info in row.get("addr_info", []):
            if info.get("family") == "inet":
                addresses.append(f"{info.get('local')}/{info.get('prefixlen')}")
        interfaces.append(
            {
                "name": name,
                "state": row.get("operstate", "UNKNOWN"),
                "mac": row.get("address", ""),
                "addresses": addresses,
            }
        )
    return interfaces


def default_route():
    routes = run_json(["ip", "-j", "route", "show", "default"])
    if not routes:
        return {}
    route = routes[0]
    return {
        "interface": route.get("dev", ""),
        "gateway": route.get("gateway", ""),
        "raw": route,
    }


def prompt_choice(prompt, choices, default=None):
    if not choices:
        return ""
    choice_text = ", ".join(choices)
    suffix = f" [{default}]" if default else ""
    while True:
        answer = input(f"{prompt} ({choice_text}){suffix}: ").strip()
        if not answer and default:
            return default
        if answer in choices:
            return answer
        print("Please enter one of the listed values.")


def default_client_ip(network):
    candidate = network.network_address + 50
    if candidate in network and candidate not in {network.network_address, network.broadcast_address}:
        return str(candidate)
    candidate = network.network_address + 2
    if candidate in network and candidate not in {network.network_address, network.broadcast_address}:
        return str(candidate)
    return ""


def router_netplan(external_interface, internal_interface, internal_cidr):
    return {
        "network": {
            "version": 2,
            "renderer": "networkd",
            "ethernets": {
                external_interface: {
                    "dhcp4": True,
                    "optional": True,
                },
                internal_interface: {
                    "dhcp4": False,
                    "addresses": [internal_cidr],
                    "optional": True,
                },
            },
        }
    }


def write_temp_yaml(data):
    handle = tempfile.NamedTemporaryFile("w", delete=False, suffix=".yaml", encoding="utf-8")
    with handle:
        yaml.safe_dump(data, handle, sort_keys=False)
    return handle.name


def write_temp_text(text):
    handle = tempfile.NamedTemporaryFile("w", delete=False, suffix=".conf", encoding="utf-8")
    with handle:
        handle.write(text)
    return handle.name


def router_setup_wizard():
    print("\nRouter setup:")
    print("This optional step configures the Security VM as a two-interface router/firewall.")
    if not yes_no("Configure router mode now?", default=False):
        print("[+] Skipping router setup.")
        return

    interfaces = detected_interfaces()
    route = default_route()
    if len(interfaces) < 2:
        print("[!] Fewer than two non-loopback interfaces were detected.")
        print("    Router mode needs one external interface and one internal interface.")
        return

    print("\nDetected interfaces:")
    for item in interfaces:
        address_text = ", ".join(item["addresses"]) if item["addresses"] else "no IPv4 address"
        marker = " default route" if item["name"] == route.get("interface") else ""
        print(f"  {item['name']:12} {item['state']:8} {address_text}{marker}")

    default_external = route.get("interface") or interfaces[0]["name"]
    if route.get("gateway"):
        print(f"\nDefault external route: {default_external} via {route['gateway']}")
    else:
        print("\nNo default route was detected. Choose the internet-facing interface manually.")

    names = [item["name"] for item in interfaces]
    external_interface = prompt_choice("External/internet interface", names, default_external)
    internal_choices = [name for name in names if name != external_interface]
    internal_interface = prompt_choice("Internal/lab interface", internal_choices, internal_choices[0])

    default_internal_cidr = "192.168.11.1/24"
    if yes_no(f"Use default internal router IP {default_internal_cidr}?", default=True):
        internal_cidr = default_internal_cidr
    else:
        internal_cidr = input("Internal router IP with prefix, e.g. 192.168.11.1/24: ").strip() or default_internal_cidr

    try:
        interface = ipaddress.ip_interface(internal_cidr)
    except ValueError:
        print("[!] Invalid internal CIDR. Router setup skipped.")
        return

    network = interface.network
    client_ip = default_client_ip(network)
    netplan_data = router_netplan(external_interface, internal_interface, internal_cidr)
    netplan_temp = write_temp_yaml(netplan_data)
    sysctl_temp = write_temp_text("net.ipv4.ip_forward=1\n")
    netplan_target = "/etc/netplan/99-security-vm-router.yaml"
    sysctl_target = "/etc/sysctl.d/99-security-vm-router.conf"

    print("\nGenerated netplan:")
    print(yaml.safe_dump(netplan_data, sort_keys=False))
    print("Client device manual IPv4 settings:")
    print(f"  IP address: {client_ip or 'choose any free host IP in the internal subnet'}")
    print(f"  Prefix/mask: /{network.prefixlen}")
    print(f"  Gateway:    {interface.ip}")
    print("  DNS:        1.1.1.1, 8.8.8.8")

    print("\nCommands that will be used:")
    commands = [
        ["sudo", "cp", netplan_temp, netplan_target],
        ["sudo", "cp", sysctl_temp, sysctl_target],
        ["sudo", "sysctl", "--system"],
        ["sudo", "netplan", "generate"],
        ["sudo", "netplan", "apply"],
        ["sudo", "systemctl", "enable", "--now", "firewalld"],
        ["sudo", "firewall-cmd", "--permanent", "--zone=external", f"--add-interface={external_interface}"],
        ["sudo", "firewall-cmd", "--permanent", "--zone=internal", f"--add-interface={internal_interface}"],
        ["sudo", "firewall-cmd", "--permanent", "--zone=external", "--add-masquerade"],
        ["sudo", "firewall-cmd", "--reload"],
    ]
    for command in commands:
        print("  " + " ".join(command))

    if not yes_no("Apply router configuration now?", default=False):
        print(f"[+] Router files left for review: {netplan_temp}, {sysctl_temp}")
        return

    for command in commands:
        subprocess.run(command, check=True)
    print("[+] Router configuration applied.")
    print("[!] If your SSH/browser connection drops, reconnect using the interface address that still reaches this VM.")


def install_missing(missing):
    packages = sorted({APT_PACKAGES[item] for item in missing if item in APT_PACKAGES})
    if not packages:
        return
    print("\nMissing apt packages:")
    print("  " + " ".join(packages))
    if yes_no("Install missing packages with apt now?"):
        command = ["sudo", "apt-get", "update"]
        subprocess.run(command, check=True)
        command = ["sudo", "apt-get", "install", "-y", *packages]
        subprocess.run(command, check=True)


def test_ai_model(host, model, timeout):
    try:
        response = requests.get(f"{host}/api/tags", timeout=timeout)
        response.raise_for_status()
        models = [item.get("name") for item in response.json().get("models", [])]
        print(f"[+] AI model service reachable. Models: {', '.join(models) if models else 'none returned'}")
        if model not in models:
            print(f"[!] Model {model!r} was not listed. You can still try it if the service accepts aliases.")
    except requests.RequestException as exc:
        print(f"[!] Could not reach AI model service at {host}: {exc}")


def main():
    print("Tailscale is required for this project.")
    print("Please head over to Tailscale or the admin console to get your AI machine IP address.")
    print("Example AI service/Tailscale endpoint: http://<ai-machine-ip>:11434\n")

    ai_ip = input("What is the IP address of your AI machine? ").strip()
    if not ai_ip:
        ai_ip = "127.0.0.1"

    ai_model_port = input("What port is the AI service running on? [11434] ").strip() or "11434"
    ai_model_name = input("What AI model should be used? [llama3.1:8b] ").strip() or "llama3.1:8b"
    ai_model_host = f"http://{ai_ip}:{ai_model_port}"

    print("\nChecking required system tools:")
    missing = [name for name, binary in REQUIRED_TOOLS.items() if not check_tool(name, binary)]
    install_missing(missing)

    config = DEFAULT_CONFIG.copy()
    config["ai_model"]["host"] = ai_model_host
    config["ai_model"]["model"] = ai_model_name

    config_path = Path("config.yaml")
    if config_path.exists() and not yes_no("config.yaml already exists. Replace it?"):
        print("[+] Keeping existing config.yaml")
    else:
        save_config(config, config_path)
        print("[+] Wrote config.yaml")

    db_path = config["database"]["path"]
    init_db(db_path)
    print(f"[+] SQLite database initialized: {db_path}")

    Path("evidence/sample_alerts").mkdir(parents=True, exist_ok=True)
    Path("evidence/sample_pcaps").mkdir(parents=True, exist_ok=True)

    test_ai_model(ai_model_host, ai_model_name, config["ai_model"]["timeout_seconds"])
    router_setup_wizard()

    print("\nNext steps:")
    print("  1. Confirm Suricata is writing /var/log/suricata/eve.json")
    print("  2. Run: python -m app.main ingest --config config.yaml")
    print("  3. Run: python -m app.main dashboard --config config.yaml --host 0.0.0.0 --port 8000")


if __name__ == "__main__":
    main()

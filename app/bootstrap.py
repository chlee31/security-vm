"""Interactive host setup for sensors, permissions, and configuration.

Bootstrap discovers interfaces and installed tools, prepares sensor settings,
and writes application configuration. Privileged sensor changes are kept here
rather than mixed into the normal ingestion path.
"""

import json
import shutil
import subprocess
import tempfile
from copy import deepcopy
from pathlib import Path

import requests
from app.config import DEFAULT_CONFIG, load_config, save_config
from app.database import init_db


REQUIRED_TOOLS = {
    "iproute2": "ip",
    "suricata": "suricata",
    "sqlite3": "sqlite3",
    "zeek": "zeek",
    "zeekctl": "zeekctl",
    "zkg": "zkg",
}

APT_PACKAGES = {
    "iproute2": "iproute2",
    "suricata": "suricata",
    "sqlite3": "sqlite3",
}

TOOL_PATH_CANDIDATES = {
    "zeek": ["zeek", "/usr/bin/zeek", "/usr/local/bin/zeek", "/opt/zeek/bin/zeek"],
    "zeekctl": ["zeekctl", "/usr/bin/zeekctl", "/usr/local/bin/zeekctl", "/opt/zeek/bin/zeekctl"],
    "zkg": ["zkg", "/usr/bin/zkg", "/usr/local/bin/zkg", "/opt/zeek/bin/zkg"],
}

COMMUNITY_ID_SEED = 0


def yes_no(prompt, default=False):
    """Prompt for a yes-or-no answer and apply the configured default."""
    suffix = "Y/n" if default else "y/N"
    answer = input(f"{prompt} [{suffix}]: ").strip().lower()
    if not answer:
        return default
    return answer in {"y", "yes"}


def check_tool(name, binary):
    """Check tool and return a normalized status."""
    path = resolve_tool_path(name, binary)
    status = "installed" if path else "missing"
    print(f"{name:10} {status:10} {path or ''}")
    return bool(path)


def resolve_tool_path(name, binary):
    """Resolve the usable tool path from configured and system locations."""
    candidates = TOOL_PATH_CANDIDATES.get(name, [binary])
    for candidate in candidates:
        path = shutil.which(candidate) if "/" not in candidate else candidate
        if path and Path(path).exists():
            return str(path)
    return ""


def detect_os_release(path="/etc/os-release"):
    """Read the Linux distribution identity and version from os-release."""
    values = {}
    try:
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key] = value.strip().strip('"')
    except OSError:
        pass
    return {
        "id": values.get("ID", "unknown").lower(),
        "version_id": values.get("VERSION_ID", ""),
        "pretty_name": values.get("PRETTY_NAME", "Unknown operating system"),
    }


def version_tuple(value):
    """Convert a dotted version string into comparable major and minor integers."""
    try:
        parts = str(value).split(".")
        return tuple(int(part) for part in parts[:2])
    except ValueError:
        return (0, 0)


def zeek_os_recommendation(os_release):
    """Report whether the detected OS meets the tested Zeek requirement."""
    is_ubuntu = os_release.get("id") == "ubuntu"
    supported_version = version_tuple(os_release.get("version_id")) >= (22, 4)
    return {
        **os_release,
        "recommended": bool(is_ubuntu and supported_version),
        "minimum": "Ubuntu 22.04",
        "message": (
            "Recommended for this project."
            if is_ubuntu and supported_version
            else "Not recommended for this project. Use Ubuntu 22.04 or newer for the tested Zeek bootstrap path."
        ),
    }


def run_json(command):
    """Run a command expected to return JSON, falling back to an empty list."""
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        return json.loads(result.stdout or "[]")
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError):
        return []


def detected_interfaces():
    """Return interfaces detected from the local operating environment."""
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


def prompt_choice(prompt, choices, default=None):
    """Prompt until the user selects one of the allowed values."""
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


def write_temp_text(text):
    """Write configuration text to a temporary file and return its path."""
    handle = tempfile.NamedTemporaryFile("w", delete=False, suffix=".conf", encoding="utf-8")
    with handle:
        handle.write(text)
    return handle.name


def install_official_zeek(os_release):
    """Install Zeek from the supported upstream repository when OS-compatible."""
    recommendation = zeek_os_recommendation(os_release)
    if not recommendation["recommended"]:
        print(f"[!] Zeek automatic setup skipped: {recommendation['message']}")
        return False
    if not yes_no("Install Zeek from the official Zeek OBS repository now?", default=True):
        return False

    version_id = os_release["version_id"]
    repository_url = f"https://download.opensuse.org/repositories/security:/zeek/xUbuntu_{version_id}/"
    repository_line = f"deb {repository_url} /\n"
    key_url = f"{repository_url}Release.key"
    repo_temp = write_temp_text(repository_line)
    key_ascii = tempfile.NamedTemporaryFile(delete=False, suffix=".key").name
    keyring = tempfile.NamedTemporaryFile(delete=False, suffix=".gpg").name
    try:
        response = requests.get(key_url, timeout=30)
        response.raise_for_status()
        Path(key_ascii).write_bytes(response.content)
        subprocess.run(["gpg", "--batch", "--yes", "--dearmor", "--output", keyring, key_ascii], check=True)
        subprocess.run(
            ["sudo", "install", "-m", "0644", repo_temp, "/etc/apt/sources.list.d/security-zeek.list"],
            check=True,
        )
        subprocess.run(
            ["sudo", "install", "-m", "0644", keyring, "/etc/apt/trusted.gpg.d/security_zeek.gpg"],
            check=True,
        )
        subprocess.run(["sudo", "apt-get", "update"], check=True)
        subprocess.run(["sudo", "apt-get", "install", "-y", "zeek"], check=True)
        return bool(resolve_tool_path("zeek", "zeek"))
    except (OSError, requests.RequestException, subprocess.CalledProcessError) as exc:
        print(f"[!] Official Zeek installation failed: {exc}")
        print(f"    Review the repository instructions for {os_release.get('pretty_name')}: {repository_url}")
        return False
    finally:
        for path in (repo_temp, key_ascii, keyring):
            try:
                Path(path).unlink()
            except OSError:
                pass


def install_missing(missing, os_release):
    """Offer to install missing apt tools and Zeek dependencies."""
    packages = sorted({APT_PACKAGES[item] for item in missing if item in APT_PACKAGES})
    if packages:
        print("\nMissing apt packages:")
        print("  " + " ".join(packages))
        if yes_no("Install missing packages with apt now?"):
            command = ["sudo", "apt-get", "update"]
            subprocess.run(command, check=True)
            command = ["sudo", "apt-get", "install", "-y", *packages]
            subprocess.run(command, check=True)
    still_missing = [
        name
        for name in ("zeek", "zeekctl", "zkg")
        if name in missing and not resolve_tool_path(name, REQUIRED_TOOLS[name])
    ]
    if still_missing:
        install_official_zeek(os_release)
    still_missing = [name for name in still_missing if not resolve_tool_path(name, REQUIRED_TOOLS[name])]
    if still_missing:
        print("\n[!] Zeek was not found after apt package checks.")
        print("    Official binary package instructions are here:")
        print("    https://docs.zeek.org/en/current/install.html")
        print("    After installing Zeek, rerun bootstrap or set zeek.log_directory in config.yaml.")


def zeek_config_directory():
    """Locate the active ZeekControl configuration directory."""
    candidates = [
        Path("/opt/zeek/etc"),
        Path("/usr/local/etc"),
        Path("/etc/zeek"),
    ]
    for path in candidates:
        if (path / "node.cfg").exists() or (path / "zeekctl.cfg").exists():
            return path
    for path in candidates:
        if path.exists():
            return path
    return Path("/opt/zeek/etc")


def zeek_setup_wizard(config):
    """Interactively select Zeek interface, JSON logging, and community packages."""
    print("\nZeek setup:")
    config.setdefault("zeek", {})["enabled"] = True
    print("[+] Zeek is a required sensor and will remain enabled.")

    detected = detected_interfaces()
    names = [item["name"] for item in detected]
    default_interface = config.get("zeek", {}).get("interface") or config.get("assets", {}).get("internal_interface", "ens37")
    if names and default_interface not in names:
        default_interface = names[0]
    interface = prompt_choice("Zeek monitoring interface", names, default_interface) if names else default_interface
    json_logs = yes_no("Use Zeek JSON logs?", default=True)
    install_packages = yes_no("Install configured Zeek community packages with zkg?", default=False)

    config["zeek"]["interface"] = interface
    config["zeek"]["json_logs"] = json_logs
    config["zeek"]["package_install_enabled"] = install_packages

    config_dir = zeek_config_directory()
    node_cfg = f"""[zeek]
type=standalone
host=localhost
interface={interface}
"""
    networks_cfg = "# Security VM internal networks can be added here.\n"
    local_lines = [
        "@load policy/protocols/conn/community-id-logging",
        "@load policy/frameworks/notice/community-id",
        f"redef CommunityID::seed = {COMMUNITY_ID_SEED};",
    ]
    if json_logs:
        local_lines.insert(0, "@load policy/tuning/json-logs")
    local_extra = "\n" + "\n".join(local_lines) + "\n"

    print(f"\nDetected Zeek config directory: {config_dir}")
    print("Generated node.cfg:")
    print(node_cfg)
    print("local.zeek addition:")
    print(local_extra.strip() or "(none)")

    if yes_no("Write Zeek node.cfg/networks.cfg/local.zeek changes now?", default=False):
        node_tmp = write_temp_text(node_cfg)
        networks_tmp = write_temp_text(networks_cfg)
        commands = [
            ["sudo", "cp", node_tmp, str(config_dir / "node.cfg")],
            ["sudo", "cp", networks_tmp, str(config_dir / "networks.cfg")],
        ]
        for command in commands:
            subprocess.run(command, check=True)
        local_path = config_dir / "local.zeek"
        existing_lines = set()
        try:
            existing_lines = {
                line.strip()
                for line in local_path.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            }
        except OSError:
            pass
        missing_lines = [line for line in local_lines if line not in existing_lines]
        if missing_lines:
            append_cmd = ["sudo", "tee", "-a", str(local_path)]
            missing_text = "\n" + "\n".join(missing_lines) + "\n"
            subprocess.run(append_cmd, input=missing_text, text=True, check=True)
        else:
            print("[+] Zeek local policies already configured.")

    zeek = resolve_tool_path("zeek", "zeek")
    zeekctl = resolve_tool_path("zeekctl", "zeekctl")
    if zeek:
        subprocess.run([zeek, "--version"], check=False)
    if zeekctl:
        subprocess.run([zeekctl, "check"], check=False)
        if yes_no("Deploy Zeek with zeekctl now?", default=False):
            subprocess.run(["sudo", zeekctl, "deploy"], check=True)
            subprocess.run([zeekctl, "status"], check=False)

    packages = config.get("zeek", {}).get("community_packages", [])
    zkg = resolve_tool_path("zkg", "zkg")
    if install_packages and packages and zkg:
        for package in packages:
            print(f"\nChecking Zeek package: {package}")
            subprocess.run([zkg, "info", package], check=False)
            if yes_no(f"Install Zeek package {package}?", default=False):
                subprocess.run(["sudo", zkg, "install", package], check=True)
        if zeekctl:
            subprocess.run([zeekctl, "check"], check=False)
    elif install_packages and not packages:
        print("[+] No Zeek community packages configured. Add reviewed package names under zeek.community_packages.")


def test_ai_model(host, model, timeout):
    """Test ai model and return a diagnostic result."""
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
    """Run this module's command-line workflow."""
    os_release = detect_os_release()
    recommendation = zeek_os_recommendation(os_release)
    print(f"Detected operating system: {recommendation['pretty_name']}")
    print(f"Zeek platform recommendation: {recommendation['message']}")
    if not recommendation["recommended"] and not yes_no("Continue bootstrap without the recommended Zeek platform?", default=False):
        return

    print("Enter the address of a reachable local AI service.")
    print("This may be localhost, a trusted LAN address, or a private overlay-network address.")
    print("Example AI service endpoint: http://<ai-machine-ip>:11434\n")

    ai_ip = input("What is the IP address of your AI machine? ").strip()
    if not ai_ip:
        ai_ip = "127.0.0.1"

    ai_model_port = input("What port is the AI service running on? [11434] ").strip() or "11434"
    ai_model_name = input("What AI model should be used? [llama3.1:8b] ").strip() or "llama3.1:8b"
    ai_model_host = f"http://{ai_ip}:{ai_model_port}"

    print("\nChecking required system tools:")
    missing = [name for name, binary in REQUIRED_TOOLS.items() if not check_tool(name, binary)]
    install_missing(missing, os_release)

    config_path = Path("config.yaml")
    config = load_config(config_path) if config_path.exists() else deepcopy(DEFAULT_CONFIG)
    config["ai_model"]["host"] = ai_model_host
    config["ai_model"]["model"] = ai_model_name
    zeek_setup_wizard(config)

    community_id_script = Path(__file__).resolve().parent.parent / "scripts" / "enable_community_id.sh"
    if config.get("zeek", {}).get("enabled") and community_id_script.exists() and yes_no(
        "Enable matching Community ID correlation in Suricata and Zeek?", default=True
    ):
        subprocess.run(["sudo", str(community_id_script)], check=True)

    if config_path.exists() and not yes_no("Update the existing config.yaml with these bootstrap settings?", default=True):
        print("[+] Keeping existing config.yaml")
    else:
        save_config(config, config_path)
        print("[+] Wrote config.yaml")

    db_path = config["database"]["path"]
    db_connection = init_db(db_path)
    db_connection.close()
    print(f"[+] SQLite database initialized: {db_path}")

    Path("evidence/sample_alerts").mkdir(parents=True, exist_ok=True)

    test_ai_model(ai_model_host, ai_model_name, config["ai_model"]["timeout_seconds"])
    print("\nNext steps:")
    print("  1. Confirm Suricata is writing /var/log/suricata/eve.json")
    print("  2. Run: python -m app.main run-all --config config.yaml")
    print("  3. Open http://127.0.0.1:8000 (use a trusted management address for remote access)")


if __name__ == "__main__":
    main()

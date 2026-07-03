import shutil
import subprocess
from pathlib import Path

import requests

from app.config import DEFAULT_CONFIG, save_config
from app.database import init_db


REQUIRED_TOOLS = {
    "tailscale": "tailscale",
    "suricata": "suricata",
    "sqlite3": "sqlite3",
    "wireshark": "wireshark",
    "tshark": "tshark",
    "dumpcap": "dumpcap",
    "firewalld": "firewall-cmd",
}

APT_PACKAGES = {
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


def test_ollama(host, model, timeout):
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

    ollama_port = input("What port is the AI service running on? [11434] ").strip() or "11434"
    ollama_model = input("What AI model should be used? [llama3.1:8b] ").strip() or "llama3.1:8b"
    ollama_host = f"http://{ai_ip}:{ollama_port}"

    print("\nChecking required system tools:")
    missing = [name for name, binary in REQUIRED_TOOLS.items() if not check_tool(name, binary)]
    install_missing(missing)

    config = DEFAULT_CONFIG.copy()
    config["ollama"]["host"] = ollama_host
    config["ollama"]["model"] = ollama_model

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

    test_ollama(ollama_host, ollama_model, config["ollama"]["timeout_seconds"])

    print("\nNext steps:")
    print("  1. Confirm Suricata is writing /var/log/suricata/eve.json")
    print("  2. Run: python -m app.main ingest --config config.yaml")
    print("  3. Run: python -m app.main dashboard --config config.yaml --host 0.0.0.0 --port 8000")


if __name__ == "__main__":
    main()

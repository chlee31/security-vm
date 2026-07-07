from pathlib import Path
from copy import deepcopy

import yaml


DEFAULT_CONFIG = {
    "system": {"mode": "alert_only", "retention_days": 7},
    "suricata": {
        "eve_json_path": "/var/log/suricata/eve.json",
        "fast_log_path": "/var/log/suricata/fast.log",
    },
    "database": {"path": "security_vm.db"},
    "pcap": {
        "rolling_dir": "/var/log/pcap",
        "incident_dir": "/var/log/incidents",
        "incident_window_minutes": 5,
        "rolling_retention_days": 2,
    },
    "ai_model": {
        "host": "http://127.0.0.1:11434",
        "model": "llama3.2:latest",
        "provider": "ollama",
        "active_profile_uid": "",
        "timeout_seconds": 90,
    },
    "firewall": {"provider": "firewalld", "block_timeout_seconds": 3600},
    "thresholds": {
        "safe_max": 29,
        "human_review_min": 30,
        "high_risk_min": 70,
        "dangerous_min": 85,
    },
    "threat_intel": {
        "cache_ttl_hours": 24,
        "virustotal_enabled": False,
        "virustotal_api_key": "",
        "otx_enabled": False,
        "otx_api_key": "",
    },
    "notifications": {
        "email": {
            "enabled": False,
            "provider": "gmail",
            "smtp_host": "smtp.gmail.com",
            "smtp_port": 587,
            "use_starttls": True,
            "sender": "",
            "username": "",
            "app_password": "",
            "recipients": [],
            "cooldown_minutes": 15,
            "dangerous_only": True,
            "dashboard_base_url": "",
        }
    },
    "assets": {
        "internal_interface": "ens37",
        "default_scores": {
            "laptop": 10,
            "desktop": 8,
            "server": 10,
            "firewall_router": 10,
            "security_appliance": 10,
            "printer": 5,
            "camera_iot": 6,
            "unknown": 6,
            "other": 6,
        },
    },
    "safelist": ["127.0.0.1", "::1"],
}


def load_config(path="config.yaml"):
    config_path = Path(path)
    if not config_path.exists():
        return deepcopy(DEFAULT_CONFIG)
    with config_path.open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle) or {}
    loaded = normalize_legacy_config_keys(loaded)
    return deep_merge(deepcopy(DEFAULT_CONFIG), loaded)


def save_config(config, path="config.yaml"):
    with Path(path).open("w", encoding="utf-8") as handle:
        yaml.safe_dump(config, handle, sort_keys=False)


def deep_merge(base, override):
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            base[key] = deep_merge(base[key], value)
        else:
            base[key] = value
    return base


def normalize_legacy_config_keys(config):
    legacy_ai = config.pop("olla" + "ma", None)
    if legacy_ai and "ai_model" not in config:
        config["ai_model"] = legacy_ai
    return config

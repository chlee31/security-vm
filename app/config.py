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
        "enabled": True,
        "rolling_dir": "/var/log/pcap",
        "directory": "/var/log/pcap",
        "incident_dir": "/var/log/incidents",
        "incident_window_minutes": 5,
        "rolling_retention_days": 2,
        "external_interface": "ens33",
        "internal_interface": "ens37",
        "rotate_seconds": 60,
        "keep_files": 60,
        "max_ai_files": 2,
        "summary_packet_limit": 20,
        "summary_timeout_seconds": 20,
    },
    "zeek": {
        "enabled": True,
        "interface": "ens37",
        "log_directory": "/opt/zeek/logs/current",
        "archive_directory": "/opt/zeek/logs",
        "json_logs": True,
        "ingest_notice": True,
        "ingest_weird": True,
        "context_logs": ["conn", "dns", "http", "ssl", "files", "notice", "weird", "ssh", "x509"],
        "community_packages": ["ncsa/bro-simple-scan", "jbaggs/anomalous-dns"],
        "package_install_enabled": False,
    },
    "incident_evidence": {
        "enabled": True,
        "root_directory": "/var/lib/security-vm/incidents",
        "seconds_before": 120,
        "seconds_after": 120,
        "preserve_automatically_for": ["human_review", "dangerous"],
        "pcap_summary_enabled": True,
        "maximum_summary_packets": 500,
        "maximum_summary_characters": 20000,
        "maximum_window_seconds": 600,
    },
    "ai_reassessment": {
        "enabled": True,
        "include_suricata": True,
        "include_zeek": True,
        "include_threat_intel": True,
        "include_asset_context": True,
        "include_pcap_summary": True,
    },
    "correlation": {"sensor_time_tolerance_seconds": 10},
    "ai_model": {
        "host": "http://127.0.0.1:11434",
        "model": "llama3.2:latest",
        "provider": "ollama",
        "active_profile_uid": "",
        "timeout_seconds": 90,
        "num_predict": 192,
        "num_ctx": 8192,
        "temperature": 0.1,
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
        "providers": {
            "otx": {"enabled": False, "api_key": "", "refresh_hours": 24},
            "threatfox": {"enabled": False, "api_key": "", "refresh_hours": 6},
            "urlhaus": {"enabled": False, "api_key": "", "refresh_hours": 6},
            "sslbl": {"enabled": False, "api_key": "", "refresh_hours": 6},
            "spamhaus_drop": {"enabled": False, "api_key": "", "refresh_hours": 24},
            "openphish": {"enabled": False, "api_key": "", "refresh_hours": 12},
            "ipsum": {"enabled": False, "api_key": "", "refresh_hours": 24},
            "feodo": {"enabled": False, "api_key": "", "refresh_hours": 24},
            "virustotal": {"enabled": False, "api_key": "", "refresh_hours": 24},
        },
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
    reassessment = config.get("ai_reassessment")
    if isinstance(reassessment, dict) and "include_otx" in reassessment:
        reassessment.setdefault("include_threat_intel", reassessment.pop("include_otx"))
    threat_intel = config.get("threat_intel")
    if isinstance(threat_intel, dict):
        providers = threat_intel.setdefault("providers", {})
        for source in ("otx", "virustotal"):
            enabled_key = f"{source}_enabled"
            api_key = f"{source}_api_key"
            if source not in providers and (enabled_key in threat_intel or api_key in threat_intel):
                providers[source] = {
                    "enabled": bool(threat_intel.get(enabled_key, False)),
                    "api_key": threat_intel.get(api_key, "") or "",
                    "refresh_hours": 24,
                }
    return config

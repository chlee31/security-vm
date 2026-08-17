"""Provide one consistent way to read and write application configuration.

``DEFAULT_CONFIG`` is the documented fallback for every supported setting. A
user's ``config.yaml`` is recursively merged over this dictionary, so the file
only needs to contain values that differ from the defaults. Configuration is
loaded when each worker starts; editing YAML does not mutate a running process,
so ``run-all`` must be restarted after operational changes.

This module does not test interfaces, model reachability, or credentials. Those
checks belong to bootstrap and runtime components. Keeping file parsing here
makes every worker interpret database paths, sensor paths, model options, and
provider settings in the same way. Its main output is an ordinary Python
dictionary consumed by ``main.py``, the workers, and the dashboard.
"""

from pathlib import Path
from copy import deepcopy

import yaml


# These defaults allow a local, minimally exposed analysis deployment. Interface
# names, sensor paths, database path, model endpoint, and research controls are
# intentionally overridable in config.yaml for each installation.
DEFAULT_CONFIG = {
    "system": {"mode": "analysis", "retention_days": 7},
    "suricata": {
        "eve_json_path": "/var/log/suricata/eve.json",
        "fast_log_path": "/var/log/suricata/fast.log",
        "start_position": "end",
    },
    "database": {"path": "security_vm.db"},
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
    "ai_reassessment": {
        "enabled": True,
        "include_suricata": True,
        "include_zeek": True,
        "include_threat_intel": True,
    },
    "ai_comparison": {
        "profile_uids": [],
        "sequential": True,
    },
    "ai_experiments": {"worker_poll_seconds": 1.0},
    "correlation": {
        "policy_version": "correlation-v1",
        "sensor_time_tolerance_seconds": 10,
        "same_sensor_window_seconds": 300,
        "zeek_context_window_seconds": 120,
        "zeek_context_limit": 100,
        "strengths": {
            "community_id": 1.0,
            "community_id_same_sensor": 0.95,
            "zeek_uid": 0.95,
            "flow_time": 0.85,
            "shared_observable": 0.82,
            "same_sensor_behavior": 0.78,
            "single_sensor": 0.5,
        },
    },
    # SUPPORTED USER SETTINGS: deployment-specific endpoint and generation
    # controls belong here or in config.yaml. Restart long-running workers after
    # edits so all processes use the same merged configuration.
    "ai_model": {
        "host": "http://127.0.0.1:11434",
        "model": "llama3.2:latest",
        "provider": "ollama",
        "active_profile_uid": "",
        "timeout_seconds": 90,  # HTTP wait limit, not a model compute limit.
        "num_predict": 1024,  # Maximum generated tokens inside num_ctx.
        "num_ctx": 8192,  # Total input plus output token window.
        "temperature": 0.0,  # Preferred baseline for repeatable runs.
        "seed": 42,  # Reproducibility aid, not a cross-model guarantee.
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
    "assets": {
        "internal_interface": "ens37",
    },
    "safelist": ["127.0.0.1", "::1"],
}


def load_config(path: str | Path = "config.yaml"):
    """Return one complete configuration assembled from defaults and YAML.

    A missing file is valid and returns a deep copy of the defaults. Deep copies
    prevent one caller from accidentally changing settings seen by another.
    Legacy keys are normalized before merging so old installations continue to
    start while new code reads only the current names.
    """
    config_path = Path(path)
    if not config_path.exists():
        return deepcopy(DEFAULT_CONFIG)
    with config_path.open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle) or {}
    loaded = normalize_legacy_config_keys(loaded)
    return deep_merge(deepcopy(DEFAULT_CONFIG), loaded)


def save_config(config, path: str | Path = "config.yaml"):
    """Write a complete configuration used by later worker restarts.

    Dashboard/admin changes call this helper. It does not hot-reload already
    running ingestion or AI workers; the launcher must be restarted for those
    processes to read the new values.
    """
    with Path(path).open("w", encoding="utf-8") as handle:
        yaml.safe_dump(config, handle, sort_keys=False)


def deep_merge(base, override):
    """Apply nested user overrides without dropping sibling default settings."""
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            base[key] = deep_merge(base[key], value)
        else:
            base[key] = value
    return base


def normalize_legacy_config_keys(config):
    """Translate supported old keys and remove retired active-response settings.

    This migration happens in memory when YAML is loaded. It lets historical
    files run under the current passive-analysis design without keeping legacy
    names throughout the application.
    """
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
    # Response-era settings remain ignored by the passive analysis runtime.
    for retired_key in ("firewall", "notifications"):
        config.pop(retired_key, None)
    config.setdefault("system", {})["mode"] = "analysis"
    return config

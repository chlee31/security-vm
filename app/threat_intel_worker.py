"""Run the background loop that keeps bulk threat-intelligence feeds current.

The worker reloads config.yaml each cycle, checks each provider's last successful
refresh, and downloads only feeds that are due. Parsed indicators replace that
provider's cache in one transaction, preventing a partial download from leaving
half an IOC set. It writes provider status, normalized indicators, and sanitized
errors to SQLite, then sleeps until the next check. Cases query this local cache
before AI analysis; API keys and raw provider responses are not sent to models.
"""

import time
from datetime import datetime, timezone

from app.config import load_config
from app.database import init_db, insert_app_event, threat_intel_source_rows
from app.threat_intel import FETCHERS, provider_config, refresh_provider
from app.security import redact_secrets


def parse_time(value):
    """Normalize a saved provider timestamp to UTC for refresh comparisons."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def refresh_due_providers(conn, config):
    """Refresh each enabled, due provider and return sanitized outcome records."""
    states = threat_intel_source_rows(conn)
    now = datetime.now(timezone.utc)
    results = []
    for source in FETCHERS:
        settings = provider_config(config, source)
        if not settings["enabled"]:
            continue
        last_success = parse_time(states.get(source, {}).get("last_success"))
        interval_seconds = max(1, settings["refresh_hours"]) * 3600
        if last_success and (now - last_success).total_seconds() < interval_seconds:
            continue
        try:
            result = refresh_provider(conn, config, source)
            insert_app_event(conn, "info", "threat_intel", f"Scheduled {source} refresh completed", result)
            results.append(result)
        except Exception as exc:
            insert_app_event(conn, "error", "threat_intel", f"Scheduled {source} refresh failed: {exc}")
            results.append({"source": source, "status": "failed", "error": redact_secrets(exc, config)})
    return results


def run_threat_intel_worker(config_path, poll_seconds=300):
    """Reload configuration and refresh due feeds on a background schedule."""
    config = load_config(config_path)
    conn = init_db(config.get("database", {}).get("path", "security_vm.db"))
    insert_app_event(conn, "info", "threat_intel", "Threat-intelligence feed worker started")
    while True:
        config = load_config(config_path)
        refresh_due_providers(conn, config)
        time.sleep(poll_seconds)

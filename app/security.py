"""Redact configured credentials before errors or status reach logs and APIs."""

import re


SECRET_PATTERN = re.compile(
    r"(?i)(api[_-]?key|token|authorization|x-otx-api-key|x-apikey|app_password)"
    r"([\s\"':=]+)([^\s&,;\"'}]+)"
)


def configured_secrets(config):
    """Collect credential values that must be removed from displayed text."""
    secrets = set()
    threat_intel = (config or {}).get("threat_intel", {})
    for key, value in threat_intel.items():
        if "key" in str(key).lower() and isinstance(value, str) and value.strip():
            secrets.add(value.strip())
    for provider in (threat_intel.get("providers") or {}).values():
        value = (provider or {}).get("api_key")
        if isinstance(value, str) and value.strip():
            secrets.add(value.strip())
    return secrets


def redact_secrets(value, config=None):
    """Mask known credential patterns and configured secret values."""
    text = str(value or "")
    for secret in configured_secrets(config):
        text = text.replace(secret, "***")
    return SECRET_PATTERN.sub(lambda match: f"{match.group(1)}{match.group(2)}***", text)

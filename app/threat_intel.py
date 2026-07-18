import csv
import io
import ipaddress
import json
from urllib.parse import urlsplit

import requests

from app.security import redact_secrets

from app.database import (
    replace_threat_intel_indicators,
    threat_intel_provider_results,
    threat_intel_source_rows,
    threat_intel_usage_summary,
    update_threat_intel_source,
)


PROVIDERS = {
    "otx": {
        "label": "AlienVault OTX",
        "kind": "live_api",
        "requires_key": True,
        "description": "Live IP reputation and subscribed pulse context.",
    },
    "threatfox": {
        "label": "ThreatFox",
        "kind": "bulk_api",
        "requires_key": True,
        "description": "Malware IOCs, C2 infrastructure, families, confidence, and references.",
    },
    "urlhaus": {
        "label": "URLhaus",
        "kind": "bulk_feed",
        "requires_key": True,
        "description": "Active malware-delivery URLs and associated hosts.",
    },
    "sslbl": {
        "label": "SSLBL",
        "kind": "bulk_feed",
        "requires_key": False,
        "description": "Recent botnet C2 IPs, malicious certificates, and JA3 fingerprints.",
    },
    "spamhaus_drop": {
        "label": "Spamhaus DROP",
        "kind": "bulk_feed",
        "requires_key": False,
        "description": "High-confidence malicious IPv4 and IPv6 network ranges.",
    },
    "openphish": {
        "label": "OpenPhish Community",
        "kind": "bulk_feed",
        "requires_key": False,
        "description": "Community phishing URL feed refreshed by the publisher every 12 hours.",
    },
    "ipsum": {
        "label": "IPsum",
        "kind": "bulk_feed",
        "requires_key": False,
        "description": "Consensus IP reputation based on appearances across public blocklists.",
    },
    "feodo": {
        "label": "Feodo Tracker",
        "kind": "bulk_feed",
        "requires_key": False,
        "description": "Botnet C2 feed; currently expected to contain few or no active entries.",
    },
    "virustotal": {
        "label": "VirusTotal",
        "kind": "post_ai_api",
        "requires_key": True,
        "description": "Post-AI IP reputation verification used only when the AI classification is Dangerous.",
    },
}

PRE_AI_PROVIDERS = frozenset(name for name in PROVIDERS if name != "virustotal")


def provider_config(config, source):
    threat_intel = config.get("threat_intel", {})
    configured = threat_intel.get("providers", {}).get(source, {})
    legacy_enabled = threat_intel.get(f"{source}_enabled", False)
    legacy_key = threat_intel.get(f"{source}_api_key", "")
    return {
        "enabled": bool(configured.get("enabled", legacy_enabled)),
        "api_key": configured.get("api_key", legacy_key) or "",
        "refresh_hours": int(configured.get("refresh_hours", 24)),
    }


def sanitized_provider_status(config, conn=None):
    source_rows = threat_intel_source_rows(conn) if conn else {}
    usage_rows = threat_intel_usage_summary(conn) if conn else {}
    items = []
    for name, metadata in PROVIDERS.items():
        settings = provider_config(config, name)
        state = source_rows.get(name, {})
        usage = usage_rows.get(name, {})
        enabled = settings["enabled"]
        key_ready = bool(settings["api_key"])
        if not enabled:
            status = "not_active"
        elif metadata["requires_key"] and not key_ready:
            status = "missing_key"
        else:
            status = state.get("status") or ("ready_to_refresh" if metadata["kind"] != "live_api" else "active")
        items.append(
            {
                "name": name,
                **metadata,
                "enabled": enabled,
                "api_key_configured": key_ready,
                "refresh_hours": settings["refresh_hours"],
                "status": status,
                "indicator_count": int(state.get("indicator_count") or 0),
                "last_attempt": state.get("last_attempt"),
                "last_success": state.get("last_success"),
                "last_error": state.get("last_error") or "",
                "usage_count": int(usage.get("usage_count") or 0),
                "last_used": usage.get("last_used"),
                "usage_stages": usage.get("stages") or {},
            }
        )
    return items


def ai_provider_status(config, conn):
    """Return provider state safe for prompts, APIs, and stored evidence."""
    return [
        {
            "name": item["name"],
            "label": item["label"],
            "kind": item["kind"],
            "enabled": item["enabled"],
            "status": item["status"],
            "indicator_count": item["indicator_count"],
            "last_success": item["last_success"],
        }
        for item in sanitized_provider_status(config, conn)
    ]


def provider_evidence_for_indicator(conn, config, indicator, indicator_type="ip"):
    providers = ai_provider_status(config, conn)
    if not indicator:
        return [
            {**provider, "match_count": 0, "matches": [], "result": "unavailable"}
            for provider in providers
        ]
    results = threat_intel_provider_results(
        conn,
        indicator,
        providers,
        indicator_type=indicator_type,
    )
    for item in results:
        if item.get("name") == "virustotal":
            item["matches"] = []
            item["match_count"] = 0
            item["result"] = "not_requested" if item.get("enabled") else "not_active"
    return results


def _get(url, timeout=60):
    response = requests.get(url, timeout=timeout, headers={"User-Agent": "security-vm-threat-intel/1.0"})
    response.raise_for_status()
    return response


def _url_indicators(url, source, category, confidence, raw=None):
    items = [{"indicator": url, "indicator_type": "url", "category": category, "confidence": confidence, "raw_data": raw}]
    try:
        host = (urlsplit(url).hostname or "").lower()
        if host:
            try:
                host_type = "ip" if ipaddress.ip_address(host) else "domain"
            except ValueError:
                host_type = "domain"
            items.append({"indicator": host, "indicator_type": host_type, "category": category, "confidence": confidence, "raw_data": raw})
    except ValueError:
        pass
    return items


def fetch_threatfox(settings):
    response = requests.post(
        "https://threatfox-api.abuse.ch/api/v1/",
        headers={"Auth-Key": settings["api_key"], "Content-Type": "application/json"},
        json={"query": "get_iocs", "days": 7},
        timeout=90,
    )
    response.raise_for_status()
    payload = response.json()
    if payload.get("query_status") != "ok":
        raise ValueError(f"ThreatFox returned {payload.get('query_status', 'an unknown status')}")
    indicators = []
    for row in payload.get("data") or []:
        original = str(row.get("ioc") or "").strip()
        ioc_type = str(row.get("ioc_type") or "").lower()
        if not original:
            continue
        value = original
        normalized_type = ioc_type.replace("_", "")
        if ioc_type == "ip:port":
            value = original.rsplit(":", 1)[0].strip("[]")
            normalized_type = "ip"
        elif "sha256" in ioc_type:
            normalized_type = "sha256"
        elif "md5" in ioc_type:
            normalized_type = "md5"
        indicators.append(
            {
                "indicator": value.lower() if normalized_type in {"domain", "url"} else value,
                "indicator_type": normalized_type,
                "category": row.get("threat_type"),
                "malware_family": row.get("malware_printable") or row.get("malware"),
                "confidence": int(row.get("confidence_level") or 50),
                "first_seen": row.get("first_seen"),
                "last_seen": row.get("last_seen"),
                "source_reference": row.get("reference") or row.get("threatfox_url"),
                "raw_data": row,
            }
        )
    return indicators


def fetch_urlhaus(settings):
    url = f"https://urlhaus-api.abuse.ch/v2/files/exports/{settings['api_key']}/recent.csv"
    text = _get(url, timeout=90).text
    lines = [line for line in text.splitlines() if line.strip() and not line.startswith("#")]
    if not lines:
        return []
    rows = csv.DictReader(io.StringIO("\n".join(lines)))
    indicators = []
    for row in rows:
        url_value = row.get("url") or row.get("URL") or ""
        indicators.extend(_url_indicators(url_value, "urlhaus", "malware_delivery", 90, row))
    return indicators


def _csv_rows(url):
    lines = [line for line in _get(url).text.splitlines() if line.strip() and not line.startswith("#")]
    return list(csv.reader(lines))


def fetch_sslbl(_settings):
    indicators = []
    for row in _csv_rows("https://sslbl.abuse.ch/blacklist/sslipblacklist.csv"):
        if len(row) < 3:
            continue
        indicators.append({"indicator": row[1].strip(), "indicator_type": "ip", "category": "botnet_c2", "confidence": 90, "first_seen": row[0].strip(), "raw_data": row})
    for row in _csv_rows("https://sslbl.abuse.ch/blacklist/sslblacklist.csv"):
        if len(row) < 3:
            continue
        indicators.append({"indicator": row[1].strip().lower(), "indicator_type": "sha1_certificate", "category": row[2].strip(), "confidence": 90, "first_seen": row[0].strip(), "raw_data": row})
    for row in _csv_rows("https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv"):
        if len(row) < 4:
            continue
        indicators.append({"indicator": row[0].strip().lower(), "indicator_type": "ja3", "category": row[3].strip(), "confidence": 55, "first_seen": row[1].strip(), "last_seen": row[2].strip(), "raw_data": row})
    return indicators


def fetch_spamhaus_drop(_settings):
    indicators = []
    for url in ("https://www.spamhaus.org/drop/drop_v4.json", "https://www.spamhaus.org/drop/drop_v6.json"):
        for line in _get(url).text.splitlines():
            try:
                row = json.loads(line)
            except (TypeError, ValueError):
                continue
            cidr = row.get("cidr")
            if not cidr:
                continue
            indicators.append({"indicator": cidr, "indicator_type": "cidr", "category": "drop", "confidence": 100, "source_reference": row.get("sblid"), "raw_data": row})
    return indicators


def fetch_openphish(_settings):
    indicators = []
    text = _get("https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt").text
    for line in text.splitlines():
        url = line.strip()
        if url and not url.startswith("#"):
            indicators.extend(_url_indicators(url, "openphish", "phishing", 75))
    return indicators


def fetch_ipsum(_settings):
    indicators = []
    text = _get("https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt").text
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) < 2:
            continue
        try:
            score = int(fields[1])
            ipaddress.ip_address(fields[0])
        except ValueError:
            continue
        confidence = 85 if score >= 6 else 65 if score >= 3 else 35
        indicators.append({"indicator": fields[0], "indicator_type": "ip", "category": f"consensus_{score}", "confidence": confidence, "raw_data": {"list_count": score}})
    return indicators


def fetch_feodo(_settings):
    rows = _get("https://feodotracker.abuse.ch/downloads/ipblocklist.json").json()
    if isinstance(rows, dict):
        rows = rows.get("data") or []
    return [
        {
            "indicator": row.get("ip_address"),
            "indicator_type": "ip",
            "category": "botnet_c2",
            "malware_family": row.get("malware"),
            "confidence": 90,
            "first_seen": row.get("first_seen"),
            "last_seen": row.get("last_online"),
            "raw_data": row,
        }
        for row in rows
        if row.get("ip_address")
    ]


def lookup_virustotal_ip(settings, ip_address):
    try:
        address = ipaddress.ip_address(str(ip_address or "").strip())
    except ValueError as exc:
        raise ValueError("VirusTotal lookup requires a valid IP address") from exc
    if not address.is_global:
        raise ValueError("VirusTotal lookup is limited to public IP addresses")
    api_key = str(settings.get("api_key") or "").strip()
    if not api_key:
        raise ValueError("VirusTotal requires an API key")

    response = requests.get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{address}",
        headers={"accept": "application/json", "x-apikey": api_key},
        timeout=30,
    )
    response.raise_for_status()
    payload = response.json()
    attributes = (payload.get("data") or {}).get("attributes") or {}
    stats = attributes.get("last_analysis_stats") or {}
    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    harmless = int(stats.get("harmless") or 0)
    reputation = "malicious" if malicious else "suspicious" if suspicious else "benign"
    return {
        "indicator": str(address),
        "indicator_type": "ip",
        "source": "virustotal",
        "reputation": reputation,
        "malicious_count": malicious,
        "suspicious_count": suspicious,
        "harmless_count": harmless,
        "lookup_result": f"malicious {malicious}; suspicious {suspicious}; harmless {harmless}",
        "raw_response": json.dumps(payload, separators=(",", ":")),
    }


FETCHERS = {
    "threatfox": fetch_threatfox,
    "urlhaus": fetch_urlhaus,
    "sslbl": fetch_sslbl,
    "spamhaus_drop": fetch_spamhaus_drop,
    "openphish": fetch_openphish,
    "ipsum": fetch_ipsum,
    "feodo": fetch_feodo,
}


def refresh_provider(conn, config, source):
    if source not in PROVIDERS:
        raise ValueError("Unknown threat-intelligence provider")
    settings = provider_config(config, source)
    metadata = PROVIDERS[source]
    if not settings["enabled"]:
        raise ValueError(f"{metadata['label']} is not active")
    if metadata["requires_key"] and not settings["api_key"]:
        raise ValueError(f"{metadata['label']} requires an API key")
    if source not in FETCHERS:
        raise ValueError(f"{metadata['label']} does not support bulk refresh")
    update_threat_intel_source(conn, source, "refreshing")
    try:
        indicators = FETCHERS[source](settings)
        count = replace_threat_intel_indicators(conn, source, indicators)
        return {"source": source, "status": "ready", "indicator_count": count}
    except Exception as exc:
        update_threat_intel_source(conn, source, "failed", redact_secrets(exc, config))
        raise

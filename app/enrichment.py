import ipaddress
import json

import requests


def enrichment_plan(config):
    threat_intel = config.get("threat_intel", {})
    ttl_hours = int(threat_intel.get("cache_ttl_hours", 24))
    return {
        "cache_ttl_hours": ttl_hours,
        "sources": [
            {
                "name": "local-ip-classification",
                "enabled": True,
                "live_api": False,
                "status": "active",
            },
            {
                "name": "otx",
                "enabled": bool(threat_intel.get("otx_enabled")),
                "live_api": True,
                "status": "active" if threat_intel.get("otx_enabled") else "disabled",
            },
            {
                "name": "virustotal",
                "enabled": bool(threat_intel.get("virustotal_enabled")),
                "live_api": True,
                "status": "active" if threat_intel.get("virustotal_enabled") else "planned_disabled",
            },
        ],
    }


def should_external_enrich_ip(ip_address):
    try:
        parsed = ipaddress.ip_address(ip_address)
    except ValueError:
        return False, "invalid_ip"

    if parsed.is_private:
        return False, "private_ip"
    if parsed.is_loopback:
        return False, "loopback_ip"
    if parsed.is_multicast:
        return False, "multicast_ip"
    if parsed.is_reserved:
        return False, "reserved_ip"
    return True, "public_ip"


def summarize_otx_response(data):
    pulse_info = data.get("pulse_info") or {}
    pulses = pulse_info.get("pulses") or []
    pulse_count = pulse_info.get("count")
    if pulse_count is None:
        pulse_count = len(pulses)

    malicious_count = 0
    suspicious_count = 0
    names = []
    for pulse in pulses:
        name = str(pulse.get("name") or "")
        names.append(name)
        tags = " ".join(str(tag) for tag in (pulse.get("tags") or []))
        text = f"{name} {tags}".lower()
        if any(word in text for word in ("malware", "c2", "botnet", "phishing", "ransomware")):
            malicious_count += 1
        else:
            suspicious_count += 1

    if malicious_count:
        reputation = "malicious"
    elif suspicious_count or pulse_count:
        reputation = "suspicious"
    else:
        reputation = "benign"

    return {
        "reputation": reputation,
        "malicious_count": malicious_count,
        "suspicious_count": suspicious_count,
        "lookup_result": ", ".join(names[:5]) if names else "No OTX pulses found",
    }


def lookup_otx_ip(config, ip_address):
    threat_intel = config.get("threat_intel", {})
    api_key = threat_intel.get("otx_api_key")
    if not threat_intel.get("otx_enabled") or not api_key:
        raise ValueError("OTX is not enabled or API key is missing")

    should_lookup, reason = should_external_enrich_ip(ip_address)
    if not should_lookup:
        return {
            "indicator": ip_address,
            "source": "otx",
            "reputation": "skipped",
            "malicious_count": 0,
            "suspicious_count": 0,
            "lookup_result": reason,
            "raw_response": json.dumps({"skipped": reason}),
        }

    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_address}/general"
    response = requests.get(url, headers={"X-OTX-API-KEY": api_key}, timeout=15)
    response.raise_for_status()
    data = response.json()
    summary = summarize_otx_response(data)
    return {
        "indicator": ip_address,
        "source": "otx",
        **summary,
        "raw_response": json.dumps(data, sort_keys=True),
    }


def test_otx_connection(api_key):
    if not api_key:
        raise ValueError("OTX API key is missing")

    response = requests.get(
        "https://otx.alienvault.com/api/v1/pulses/subscribed?page=1",
        headers={"X-OTX-API-KEY": api_key},
        timeout=10,
    )
    response.raise_for_status()
    data = response.json()
    return {
        "status": "connected",
        "pulse_count": data.get("count", 0),
        "next": bool(data.get("next")),
    }

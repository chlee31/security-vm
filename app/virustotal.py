import ipaddress
from datetime import datetime, timedelta, timezone

import requests

from app.database import (
    insert_virustotal_verification,
    latest_threat_intel_for_ip,
    record_threat_intel_usage,
    upsert_threat_intel_lookup,
)
from app.threat_intel import lookup_virustotal_ip, provider_config


def _lookup_time(value):
    try:
        parsed = datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def eligible_ip(value):
    try:
        address = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return False
    return bool(address.is_global and address not in ipaddress.ip_network("100.64.0.0/10"))


def verdict(result):
    if int(result.get("malicious_count") or 0):
        return "malicious", "corroborated"
    if int(result.get("suspicious_count") or 0):
        return "suspicious", "corroborated"
    return "no_detection", "not_corroborated"


def _store(conn, detection_id, result, ai_report_id, stage):
    insert_virustotal_verification(conn, detection_id, result, ai_report_id, stage)
    return result


def verify_dangerous(
    conn,
    config,
    alert,
    detection_id,
    alert_id,
    ai_report,
    ai_report_id=None,
    stage="initial",
    force_refresh=False,
):
    if str(ai_report.get("classification") or "").strip().lower() != "dangerous":
        return [
            _store(
                conn,
                detection_id,
                {
                    "request_state": "not_requested",
                    "verdict": "unknown",
                    "interpretation": "unavailable",
                    "details": {"reason": "AI classification was not Dangerous."},
                },
                ai_report_id,
                stage,
            )
        ]
    settings = provider_config(config, "virustotal")
    if not settings.get("enabled") or not settings.get("api_key"):
        return [
            _store(
                conn,
                detection_id,
                {
                    "request_state": "unavailable",
                    "verdict": "unknown",
                    "interpretation": "unavailable",
                    "details": {"reason": "VirusTotal is disabled or not configured."},
                },
                ai_report_id,
                stage,
            )
        ]

    ttl_hours = max(1, int(config.get("threat_intel", {}).get("cache_ttl_hours", 24)))
    results = []
    for value in dict.fromkeys([alert.get("src_ip"), alert.get("dest_ip")]):
        if not eligible_ip(value):
            continue
        cached = latest_threat_intel_for_ip(conn, value, "virustotal")
        cached_at = _lookup_time((cached or {}).get("lookup_time"))
        if (
            not force_refresh
            and cached
            and cached_at
            and datetime.now(timezone.utc) - cached_at < timedelta(hours=ttl_hours)
        ):
            result = {**cached, "indicator": value, "source": "virustotal", "cached": True}
            result["request_state"] = "cached"
        else:
            try:
                result = lookup_virustotal_ip(settings, value)
            except requests.HTTPError as exc:
                state = "rate_limited" if getattr(exc.response, "status_code", None) == 429 else "failed"
                result = {
                    "indicator": value,
                    "request_state": state,
                    "verdict": "unknown",
                    "interpretation": "unavailable",
                    "error": f"VirusTotal HTTP {getattr(exc.response, 'status_code', 'error')}",
                    "cached": False,
                }
                results.append(_store(conn, detection_id, result, ai_report_id, stage))
                continue
            except requests.RequestException as exc:
                result = {
                    "indicator": value,
                    "request_state": "unavailable",
                    "verdict": "unknown",
                    "interpretation": "unavailable",
                    "error": type(exc).__name__,
                    "cached": False,
                }
                results.append(_store(conn, detection_id, result, ai_report_id, stage))
                continue
            upsert_threat_intel_lookup(
                conn,
                result["indicator"],
                "virustotal",
                result["reputation"],
                malicious_count=result["malicious_count"],
                suspicious_count=result["suspicious_count"],
                lookup_result=result["lookup_result"],
                raw_response=result["raw_response"],
                alert_id=alert_id,
                detection_id=detection_id,
            )
            result["cached"] = False
            result["request_state"] = verdict(result)[0]
        result["verdict"], result["interpretation"] = verdict(result)
        result["details"] = {"lookup_result": result.get("lookup_result"), "source": "virustotal"}
        record_threat_intel_usage(
            conn,
            detection_id,
            alert_id,
            value,
            "ip",
            "virustotal",
            f"post_{stage}_verification",
            result,
        )
        results.append(_store(conn, detection_id, result, ai_report_id, stage))
    if not results:
        results.append(
            _store(
                conn,
                detection_id,
                {
                    "request_state": "unavailable",
                    "verdict": "unknown",
                    "interpretation": "unavailable",
                    "details": {"reason": "No valid global IP address was available."},
                },
                ai_report_id,
                stage,
            )
        )
    return results

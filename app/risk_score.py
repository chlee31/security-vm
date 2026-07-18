import ipaddress


PYTHON_SCORE_MAX = 80
SCORING_POLICY_VERSION = "deterministic-score-v2"
CATEGORY_MAXIMUMS = {
    "sensor_severity": 20,
    "behavior_correlation": 20,
    "threat_intelligence": 20,
    "asset_direction": 10,
    "sensor_corroboration": 10,
}


def _integer(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def severity_score(priority):
    priority = _integer(priority, 4)
    if priority == 1:
        return 20
    if priority == 2:
        return 12
    if priority == 3:
        return 5
    return 3


def sensor_severity_score(alert, findings=None):
    priorities = [_integer((alert or {}).get("priority"), 4)]
    priorities.extend(_integer(item.get("severity"), 4) for item in (findings or []))
    priority = min(priorities) if priorities else 4
    points = severity_score(priority)
    return points, {
        "highest_priority": priority,
        "finding_count": len(findings or []),
        "explanation": f"Highest sensor priority {priority} contributes {points}/20.",
    }


def correlation_score(detection_type, alert_count, unique_ports, unique_hosts=0):
    alert_count = _integer(alert_count)
    unique_ports = _integer(unique_ports)
    unique_hosts = _integer(unique_hosts)
    if detection_type == "port_scan":
        if unique_ports >= 50:
            return 20
        if unique_ports >= 20:
            return 15
        if unique_ports >= 10:
            return 10
        if unique_ports >= 5:
            return 5
    if detection_type in {"dns_tunneling", "beaconing", "brute_force"}:
        if alert_count >= 30:
            return 20
        if alert_count >= 10:
            return 14
        if alert_count >= 5:
            return 8
        if alert_count >= 2:
            return 4
    if alert_count >= 20 or unique_hosts >= 20:
        return 10
    if alert_count >= 5 or unique_hosts >= 5:
        return 5
    return 0


def behavior_correlation_score(detection):
    points = correlation_score(
        detection.get("detection_type"),
        detection.get("alert_count"),
        detection.get("unique_dest_ports"),
        detection.get("unique_dest_hosts"),
    )
    return points, {
        "detection_type": detection.get("detection_type") or "unknown",
        "alert_count": _integer(detection.get("alert_count")),
        "unique_destination_ports": _integer(detection.get("unique_dest_ports")),
        "unique_destination_hosts": _integer(detection.get("unique_dest_hosts")),
        "time_window_seconds": _integer(detection.get("time_window_seconds")),
        "explanation": f"Observed behavior and time correlation contribute {points}/20.",
    }


def _threat_intel_matches(evidence_context):
    threat_intel = (evidence_context or {}).get("threat_intel") or {}
    matches = []
    for side in ("src_ip", "dest_ip"):
        block = threat_intel.get(side) or {}
        matches.extend(block.get("matches") or [])
        legacy = block.get("legacy_otx")
        if legacy:
            matches.append({**legacy, "source": "otx"})
    for observable in threat_intel.get("alert_observables") or []:
        matches.extend(observable.get("matches") or [])
    return [item for item in matches if str(item.get("source") or "").lower() != "virustotal"]


def threat_intelligence_score(evidence_context):
    provider_points = {}
    provider_details = {}
    suspicious_terms = ("malicious", "malware", "c2", "botnet", "phishing", "command")
    for match in _threat_intel_matches(evidence_context):
        source = str(match.get("source") or "unknown").lower()
        confidence = _integer(match.get("confidence"))
        text = " ".join(
            str(match.get(key) or "")
            for key in ("category", "malware_family", "reputation", "lookup_result")
        ).lower()
        points = 4
        if confidence >= 80:
            points += 2
        elif confidence >= 50:
            points += 1
        if any(term in text for term in suspicious_terms):
            points += 2
        provider_points[source] = max(provider_points.get(source, 0), min(points, 8))
        provider_details.setdefault(source, []).append(
            {
                "indicator": match.get("indicator"),
                "category": match.get("category") or match.get("reputation"),
                "confidence": match.get("confidence"),
            }
        )
    score = min(20, sum(provider_points.values()))
    return score, {
        "provider_points": provider_points,
        "matches": provider_details,
        "virustotal_excluded": True,
        "explanation": f"Cached and bulk threat intelligence contribute {score}/20; VirusTotal is verification only.",
    }


def _is_private(value):
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False


def asset_direction_score(alert, config=None, asset_context=None):
    if asset_context is None:
        assets = (config or {}).get("assets", {})
        matched = assets.get((alert or {}).get("dest_ip")) or assets.get((alert or {}).get("src_ip"))
        if isinstance(matched, dict):
            criticality_points = {"critical": 10, "high": 6, "medium": 3}
            base = criticality_points.get(str(matched.get("criticality") or "").lower(), 0)
        else:
            base = 0
    else:
        base = max(0, min(10, _integer(asset_context.get("asset_score"))))
    src_ip = (alert or {}).get("src_ip")
    dest_ip = (alert or {}).get("dest_ip")
    outbound = bool(src_ip and dest_ip and _is_private(src_ip) and not _is_private(dest_ip))
    return min(10, base + (2 if outbound else 0))


def asset_and_direction_score(alert, detection):
    context = detection.get("asset_context") or {}
    points = asset_direction_score(alert, asset_context=context)
    return points, {
        "asset_match": context.get("asset_match", "none"),
        "asset_score": _integer(context.get("asset_score")),
        "src_asset": context.get("src_asset"),
        "dest_asset": context.get("dest_asset"),
        "explanation": f"Asset criticality and traffic direction contribute {points}/10.",
    }


def sensor_corroboration_score(detection, findings=None):
    sensors = sorted({str(item.get("sensor")) for item in (findings or []) if item.get("sensor")})
    agreement = str(detection.get("agreement_state") or "single_sensor").lower()
    method = str(detection.get("correlation_method") or "single_sensor").lower()
    disputed = agreement == "disputed"
    if disputed or len(sensors) < 2:
        points = 0
    elif agreement == "supporting" and method == "community_id":
        points = 10
    elif agreement == "supporting":
        points = 7
    elif agreement == "partial":
        points = 4
    else:
        points = 0
    return points, {
        "sensors": sensors,
        "agreement_state": agreement,
        "correlation_method": method,
        "materially_disputed": disputed,
        "explanation": f"Suricata-Zeek corroboration contributes {points}/10.",
    }


def deterministic_score(alert, detection, findings=None, evidence_context=None):
    categories = {}
    details = {}
    scorers = {
        "sensor_severity": sensor_severity_score(alert, findings),
        "behavior_correlation": behavior_correlation_score(detection),
        "threat_intelligence": threat_intelligence_score(evidence_context),
        "asset_direction": asset_and_direction_score(alert, detection),
        "sensor_corroboration": sensor_corroboration_score(detection, findings),
    }
    for name, (points, explanation) in scorers.items():
        categories[name] = max(0, _integer(points))
        details[name] = explanation
    score = min(PYTHON_SCORE_MAX, sum(categories.values()))
    disputed = bool(details["sensor_corroboration"].get("materially_disputed"))
    return {
        **categories,
        "policy_version": SCORING_POLICY_VERSION,
        "category_maximums": CATEGORY_MAXIMUMS,
        "python_score": score,
        "forced_review": disputed,
        "forced_review_reason": "Materially disputed Suricata and Zeek findings." if disputed else "",
        "details": details,
    }


def cap_score(score, maximum=100):
    return max(0, min(_integer(score), int(maximum)))


def cap_python_score(score):
    return cap_score(score, PYTHON_SCORE_MAX)

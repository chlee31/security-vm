import ipaddress

from app.allowlist import is_allowlisted
from app.risk_score import cap_score


HUMAN_REVIEW_MIN = 30
HIGH_RISK_MIN = 70
DANGEROUS_MIN = 85


def confidence_adjustment(report):
    classification = str(report.get("classification", "")).lower()
    confidence = str(report.get("confidence", "")).lower()
    if classification == "safe" and confidence == "high":
        return -10
    if classification == "safe" and confidence == "medium":
        return -5
    if classification == "dangerous" and confidence == "medium":
        return 5
    if classification == "dangerous" and confidence == "high":
        return 10
    return 0


def safe_risk_adjustment(report):
    value = report.get("risk_adjustment")
    try:
        adjustment = int(value)
    except (TypeError, ValueError):
        adjustment = confidence_adjustment(report)
    return max(-10, min(10, adjustment))


def classify_score(score):
    score = cap_score(score)
    if score >= DANGEROUS_MIN:
        return "Dangerous"
    if score >= HIGH_RISK_MIN:
        return "High Risk"
    if score >= HUMAN_REVIEW_MIN:
        return "Human Review Required"
    return "Safe"


def is_private_ip(ip_address):
    try:
        return ipaddress.ip_address(ip_address).is_private
    except ValueError:
        return False


def response_target(alert):
    src_ip = alert.get("src_ip")
    dest_ip = alert.get("dest_ip")
    if src_ip and dest_ip and is_private_ip(src_ip) and not is_private_ip(dest_ip):
        return dest_ip, "outbound_destination"
    return src_ip, "source"


def decide(conn, config, alert, detection, ai_report=None):
    mode = config.get("system", {}).get("mode", "alert_only")
    if mode == "auto_response":
        mode = "prevention"
    src_ip = alert.get("src_ip")
    target_ip, target_direction = response_target(alert)
    safelist = set(config.get("safelist", []))

    if is_allowlisted(conn, src_ip) or is_allowlisted(conn, target_ip):
        return {
            "final_score": detection.get("python_initial_score", 0),
            "final_classification": "Authorized Activity",
            "final_action": "authorized_activity",
            "target_ip": target_ip,
            "target_direction": target_direction,
            "response_method": "none",
            "response_status": "allowlisted",
            "response_time_ms": 0,
        }

    score = detection.get("python_initial_score", 0)
    if ai_report:
        score += safe_risk_adjustment(ai_report)
    score = cap_score(score)

    ai_class = str((ai_report or {}).get("classification", "")).lower()
    ai_conf = str((ai_report or {}).get("confidence", "")).lower()

    forced_review = bool(detection.get("forced_review"))
    if forced_review:
        action = "human_review"
        classification = "Human Review Required"
    elif mode == "prevention" and target_ip and score >= DANGEROUS_MIN and ai_class == "dangerous" and ai_conf == "high" and target_ip not in safelist:
        action = "temporary_block"
        classification = "Dangerous"
    elif score >= DANGEROUS_MIN:
        action = "would_block"
        classification = "Dangerous"
    elif score >= HIGH_RISK_MIN:
        action = "human_review"
        classification = "High Risk"
    elif score >= HUMAN_REVIEW_MIN:
        action = "human_review"
        classification = "Human Review Required"
    else:
        action = "log_only"
        classification = "Safe"

    return {
        "final_score": score,
        "final_classification": classification,
        "final_action": action,
        "target_ip": target_ip,
        "target_direction": target_direction,
        "response_method": "firewalld" if action == "temporary_block" else "none",
        "response_status": "pending" if action == "temporary_block" else action,
        "response_time_ms": 0,
        "forced_review": forced_review,
        "forced_review_reason": detection.get("forced_review_reason") if forced_review else "",
        "llm_adjustment": safe_risk_adjustment(ai_report or {}),
    }

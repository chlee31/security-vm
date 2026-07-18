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


def decide(conn, config, alert, detection, ai_report=None):
    score = detection.get("python_initial_score", 0)
    if ai_report:
        score += safe_risk_adjustment(ai_report)
    score = cap_score(score)

    forced_review = bool(detection.get("forced_review"))
    if forced_review:
        action = "human_review"
        classification = "Human Review Required"
    elif score >= DANGEROUS_MIN:
        action = "escalate"
        classification = "Dangerous"
    elif score >= HIGH_RISK_MIN:
        action = "investigate"
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
        "target_ip": None,
        "target_direction": None,
        "response_method": "analyst_workflow",
        "response_status": action,
        "response_time_ms": 0,
        "forced_review": forced_review,
        "forced_review_reason": detection.get("forced_review_reason") if forced_review else "",
        "llm_adjustment": safe_risk_adjustment(ai_report or {}),
    }

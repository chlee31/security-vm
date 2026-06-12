from app.allowlist import is_allowlisted
from app.risk_score import cap_score


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


def decide(conn, config, alert, detection, ollama_report=None):
    mode = config.get("system", {}).get("mode", "alert_only")
    thresholds = config.get("thresholds", {})
    dangerous_min = thresholds.get("dangerous_min", 85)
    human_review_min = thresholds.get("human_review_min", 30)
    src_ip = alert.get("src_ip")
    safelist = set(config.get("safelist", []))

    if is_allowlisted(conn, src_ip):
        return {
            "final_score": detection.get("python_initial_score", 0),
            "final_classification": "Authorized Activity",
            "final_action": "authorized_activity",
            "target_ip": src_ip,
            "response_method": "none",
            "response_status": "allowlisted",
            "response_time_ms": 0,
        }

    score = detection.get("python_initial_score", 0)
    if ollama_report:
        score += int(ollama_report.get("risk_adjustment") or confidence_adjustment(ollama_report))
    score = cap_score(score)

    ollama_class = str((ollama_report or {}).get("classification", "")).lower()
    ollama_conf = str((ollama_report or {}).get("confidence", "")).lower()

    if mode == "auto_response" and score >= dangerous_min and ollama_class == "dangerous" and ollama_conf == "high" and src_ip not in safelist:
        action = "temporary_block"
        classification = "Dangerous"
    elif mode == "alert_only" and score >= dangerous_min:
        action = "would_block"
        classification = "Dangerous"
    elif score >= human_review_min:
        action = "human_review"
        classification = "Human Review Required"
    else:
        action = "log_only"
        classification = "Safe"

    return {
        "final_score": score,
        "final_classification": classification,
        "final_action": action,
        "target_ip": src_ip,
        "response_method": "firewalld" if action == "temporary_block" else "none",
        "response_status": "pending" if action == "temporary_block" else action,
        "response_time_ms": 0,
    }

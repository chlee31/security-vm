CLASSIFICATION_ACTIONS = {
    "Safe": "log_only",
    "Human Review Required": "human_review",
    "Dangerous": "escalate",
}


def normalize_classification(value):
    normalized = str(value or "").strip().lower().replace("_", " ")
    if normalized == "safe":
        return "Safe"
    if normalized == "dangerous":
        return "Dangerous"
    if normalized in {"human review", "human review required", "review"}:
        return "Human Review Required"
    return "Human Review Required"


def materially_disputed(detection):
    return str(detection.get("agreement_state") or "").strip().lower() == "disputed"


def decide(conn, config, alert, detection, ai_report=None):
    classification = normalize_classification((ai_report or {}).get("classification"))
    forced_review = bool(detection.get("forced_review")) or materially_disputed(detection)
    if forced_review:
        classification = "Human Review Required"
    action = CLASSIFICATION_ACTIONS[classification]

    return {
        "final_classification": classification,
        "final_action": action,
        "target_ip": None,
        "target_direction": None,
        "response_method": "qualitative_evidence_workflow",
        "response_status": action,
        "response_time_ms": 0,
        "forced_review": forced_review,
        "forced_review_reason": (
            detection.get("forced_review_reason")
            or ("Materially disputed Suricata and Zeek findings." if forced_review else "")
        ),
    }

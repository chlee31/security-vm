"""Apply Python-controlled qualitative classification and response policy.

The AI model recommends a classification, but Python normalizes it and can
force analyst review when sensor findings are materially disputed. No numerical
risk score is calculated here.
"""

CLASSIFICATION_ACTIONS = {
    "Safe": "log_only",
    "Analyst Review Required": "human_review",
    "Dangerous": "escalate",
}


def normalize_classification(value):
    """Accept known labels and conservatively default unknown values to review."""
    normalized = str(value or "").strip().lower().replace("_", " ")
    if normalized == "safe":
        return "Safe"
    if normalized == "dangerous":
        return "Dangerous"
    if normalized in {
        "analyst review",
        "analyst review required",
        "human review",
        "human review required",
        "review",
    }:
        return "Analyst Review Required"
    return "Analyst Review Required"


def materially_disputed(detection):
    """Return whether sensor-fusion logic recorded an unresolved disagreement."""
    return str(detection.get("agreement_state") or "").strip().lower() == "disputed"


def decide(conn, config, alert, detection, ai_report=None):
    """Map qualitative evidence to the final Python-controlled response.

    ``conn``, ``config``, and ``alert`` are retained in the signature for
    compatibility with existing callers. The current policy depends only on
    model classification plus sensor-dispute state. Low confidence, an explicit
    forced-review marker, or unresolved sensor disagreement always overrides a
    model's Safe/Dangerous label to analyst review. This is the final control
    point between model text and the application's stored action.
    """
    report = ai_report or {}
    classification = normalize_classification(report.get("classification"))
    low_confidence = str(report.get("confidence") or "").strip().lower() == "low"
    disputed = materially_disputed(detection)
    forced_review = bool(detection.get("forced_review")) or disputed or low_confidence
    if forced_review:
        classification = "Analyst Review Required"
    action = CLASSIFICATION_ACTIONS[classification]

    forced_reasons = []
    if detection.get("forced_review"):
        forced_reasons.append(
            detection.get("forced_review_reason") or "Python required analyst review."
        )
    if disputed:
        forced_reasons.append("Materially disputed Suricata and Zeek findings.")
    if low_confidence:
        forced_reasons.append("The AI model reported Low confidence.")

    return {
        "final_classification": classification,
        "final_action": action,
        "target_ip": None,
        "target_direction": None,
        "response_method": "qualitative_evidence_workflow",
        "response_status": action,
        "response_time_ms": 0,
        "forced_review": forced_review,
        "forced_review_reason": " ".join(dict.fromkeys(forced_reasons)),
    }

"""Sanitized progress callbacks for observable AI request lifecycles."""

from app.database import (
    ai_request_cancel_requested,
    create_ai_request_activity,
    update_ai_request_activity,
)
from app.security import redact_secrets


def ai_activity_callback(
    conn,
    config,
    assessment_type,
    case_uid=None,
    detection_id=None,
    comparison_uid=None,
    anonymous_slot=None,
):
    """Create a best-effort callback that cannot break model processing."""
    activity_uid = create_ai_request_activity(
        conn,
        assessment_type,
        case_uid=case_uid,
        detection_id=detection_id,
        comparison_uid=comparison_uid,
        anonymous_slot=anonymous_slot,
    )

    def progress(phase, details=None):
        safe = dict(details or {})
        if safe.get("error_message"):
            safe["error_message"] = redact_secrets(safe["error_message"], config)
        try:
            update_ai_request_activity(conn, activity_uid, phase, safe)
        except Exception:
            # Operational visibility is supplementary. SQLite contention in the
            # console path must never suppress sensor evidence or an AI result.
            return

    def cancellation_requested():
        try:
            return ai_request_cancel_requested(conn, activity_uid)
        except Exception:
            return False

    progress.cancellation_requested = cancellation_requested
    return activity_uid, progress

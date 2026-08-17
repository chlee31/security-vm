"""Record the live progress of AI requests for the Admin console.

``ai_client.py`` calls the callback created here while it prepares a prompt,
waits for the model, and finishes or fails. The callback stores a sanitized
status row in SQLite and also checks whether an administrator requested
cancellation. It returns progress information only; it does not build prompts,
choose cases, or decide a case classification. Logging is best-effort so a
monitoring failure cannot change the model result or stop case processing.
"""

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
    """Create a durable, cancellable activity record for one model invocation.

    The returned callable updates the same row as the request moves through its
    lifecycle. A small attached cancellation checker lets the streaming HTTP
    loop stop when an operator cancels the request from Admin.
    """
    activity_uid = create_ai_request_activity(
        conn,
        assessment_type,
        case_uid=case_uid,
        detection_id=detection_id,
        comparison_uid=comparison_uid,
        anonymous_slot=anonymous_slot,
    )

    def progress(phase, details=None):
        """Record and publish the latest progress state for this AI request."""
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
        """Return whether cancellation has been requested for this AI operation."""
        try:
            return ai_request_cancel_requested(conn, activity_uid)
        except Exception:
            return False

    progress.cancellation_requested = cancellation_requested
    return activity_uid, progress

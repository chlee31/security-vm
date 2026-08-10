"""Publish sanitized AI-request progress without coupling it to model logic.

The AI client reports phases such as preparing, requesting, completed, failed,
or cancelled through a callback created here. Each update is written to SQLite
for the password-protected Admin console. Errors are redacted before storage,
and observability failures are deliberately best-effort so they cannot change a
case result or terminate the model request.
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

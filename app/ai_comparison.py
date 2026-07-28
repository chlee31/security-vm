"""Run sequential multi-model assessments and preserve comparison provenance.

Each configured profile receives the same prepared case context one at a time.
The resulting reports are stored separately so analysts can compare explanations
without concurrent model loads exhausting GPU memory.
"""

from copy import deepcopy
from threading import Lock

from app.ai_activity import ai_activity_callback
from app.ai_client import ask_ai_model, build_prompt_audit
from app.case_assessment import prepare_case_context
from app.database import (
    create_ai_comparison_run,
    fail_stale_ai_comparison_runs,
    finish_ai_comparison_run,
    get_ai_profile,
    initial_ai_request_snapshot,
    insert_ai_comparison_candidate,
    insert_app_event,
    update_ai_comparison_progress,
    upsert_ai_run_audit,
)
from app.security import redact_secrets


_comparison_lock = Lock()


def _comparison_profiles(conn, config, requested_uids=None):
    """Select up to three active profiles in a deterministic order."""
    configured = requested_uids or config.get("ai_comparison", {}).get("profile_uids") or []
    uids = []
    for uid in configured:
        if uid and uid not in uids:
            uids.append(uid)
    if len(uids) != 3:
        raise ValueError("Select exactly three active AI profiles in Admin before running a comparison")
    profiles = []
    for uid in uids:
        profile = get_ai_profile(conn, uid)
        if not profile:
            raise ValueError(f"AI profile {uid} was not found")
        if profile.get("status") != "active":
            raise ValueError(f"AI profile {uid} is inactive")
        profiles.append(profile)
    return profiles


def _config_for_profile(config, profile):
    """Clone runtime configuration and substitute one comparison profile."""
    runtime = deepcopy(config)
    ai_model = runtime.setdefault("ai_model", {})
    ai_model.update(
        {
            "host": profile["host"],
            "model": profile["model"],
            "provider": profile["provider"],
            "active_profile_uid": profile["uid"],
            "timeout_seconds": int(profile.get("timeout_seconds") or 90),
            "temperature": float(
                runtime.get("ai_comparison", {}).get("temperature", 0.0)
            ),
            "seed": int(runtime.get("ai_comparison", {}).get("seed", 42)),
        }
    )
    return runtime


def _failed_report(profile):
    """Retain model provenance for audits without relying on a model response."""
    provider = profile.get("provider") or "unknown"
    model = profile.get("model") or "unknown"
    return {
        "model_provider": provider,
        "model_name": model,
        "model_identity": f"{provider}:{model}",
        "ai_profile_uid": profile.get("uid"),
    }


def _request_error(exc, config):
    """Return a useful request failure while removing configured credentials."""
    audit = getattr(exc, "audit", None) or {}
    detail = audit.get("audit_parse_error") or str(exc) or type(exc).__name__
    return redact_secrets(detail, config)


def run_model_comparison(conn, config, case_uid, requested_uids=None):
    """Run identical case evidence through selected models sequentially.

    A single prompt hash is recorded for the comparison so differences can be
    attributed to model behavior rather than different evidence packages.
    """
    if not _comparison_lock.acquire(blocking=False):
        raise ValueError(
            "Another three-model comparison is already running. "
            "Wait for it to finish before starting another."
        )

    try:
        profiles = _comparison_profiles(conn, config, requested_uids)
        max_runtime = sum(int(profile.get("timeout_seconds") or 90) for profile in profiles) + 120
        fail_stale_ai_comparison_runs(conn, max_runtime)
        workspace, alert, detection, evidence, _findings = prepare_case_context(
            conn,
            config,
            case_uid,
            assessment_type="model_comparison",
        )
        initial_snapshot = initial_ai_request_snapshot(
            conn, workspace["detection_id"]
        )
        if initial_snapshot:
            evidence_sha256 = initial_snapshot["evidence_sha256"]
            prompt_version = initial_snapshot["prompt_version"]
            stored_context = (
                (initial_snapshot.get("evidence_package") or {}).get(
                    "evidence_context"
                )
                or {}
            )
            comparison_threat_intel = stored_context.get("threat_intel") or {}
        else:
            _prompt, canonical_audit = build_prompt_audit(
                _config_for_profile(config, profiles[0]),
                alert,
                detection,
                evidence,
            )
            evidence_sha256 = canonical_audit["audit_evidence_sha256"]
            prompt_version = canonical_audit["prompt_version"]
            comparison_threat_intel = evidence.get("threat_intel") or {}
        run_id, comparison_uid = create_ai_comparison_run(
            conn,
            case_uid,
            workspace["detection_id"],
            evidence_sha256,
            prompt_version,
            threat_intel_evidence=comparison_threat_intel,
        )

        complete = 0
        errors = []
        for slot, profile in zip(("A", "B", "C"), profiles):
            _activity_uid, progress = ai_activity_callback(
                conn,
                config,
                "model_comparison",
                case_uid=case_uid,
                detection_id=workspace["detection_id"],
                comparison_uid=comparison_uid,
                anonymous_slot=slot,
            )
            try:
                request_kwargs = {
                    "evidence_context": evidence,
                    "progress_callback": progress,
                }
                if initial_snapshot:
                    request_kwargs["prepared_request"] = initial_snapshot
                report = ask_ai_model(
                    _config_for_profile(config, profile),
                    alert,
                    detection,
                    **request_kwargs,
                )
                insert_ai_comparison_candidate(
                    conn,
                    run_id,
                    slot,
                    profile["uid"],
                    report=report,
                )
                upsert_ai_run_audit(
                    conn,
                    workspace["detection_id"],
                    report,
                    assessment_type=f"model_comparison_{slot.lower()}",
                )
                complete += 1
            except Exception as exc:
                error = _request_error(exc, config)
                progress(
                    "failed",
                    {
                        "status": "failed",
                        "error_message": error,
                    },
                )
                errors.append(f"{slot}: {error}")
                insert_ai_comparison_candidate(
                    conn,
                    run_id,
                    slot,
                    profile["uid"],
                    report=_failed_report(profile),
                    error=error,
                )
                failed_audit = getattr(exc, "audit", None)
                if failed_audit:
                    upsert_ai_run_audit(
                        conn,
                        workspace["detection_id"],
                        failed_audit,
                        assessment_type=f"model_comparison_{slot.lower()}",
                    )
            update_ai_comparison_progress(conn, run_id)

        status = "complete" if complete == 3 else "partial" if complete else "failed"
        finish_ai_comparison_run(
            conn,
            run_id,
            status,
            complete,
            "; ".join(errors) or None,
        )
        insert_app_event(
            conn,
            "info" if status == "complete" else "warning",
            "ai_comparison",
            f"AI model comparison {comparison_uid} finished with status {status}",
            {
                "case_uid": case_uid,
                "comparison_uid": comparison_uid,
                "completed_candidates": complete,
                "sequential": True,
                "input_snapshot": (
                    "initial_assessment"
                    if initial_snapshot
                    else "comparison_time"
                ),
            },
        )
        return {
            "comparison_uid": comparison_uid,
            "case_uid": case_uid,
            "status": status,
            "candidate_count": complete,
            "input_snapshot": (
                "initial_assessment" if initial_snapshot else "comparison_time"
            ),
        }
    finally:
        _comparison_lock.release()

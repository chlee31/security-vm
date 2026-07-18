from copy import deepcopy

from app.ai_client import PROMPT_VERSION, ask_ai_model, build_prompt, text_sha256
from app.case_assessment import prepare_case_context
from app.database import (
    create_ai_comparison_run,
    finish_ai_comparison_run,
    get_ai_profile,
    insert_ai_comparison_candidate,
    insert_app_event,
)


def _comparison_profiles(conn, config, requested_uids=None):
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
    runtime = deepcopy(config)
    ai_model = runtime.setdefault("ai_model", {})
    ai_model.update(
        {
            "host": profile["host"],
            "model": profile["model"],
            "provider": profile["provider"],
            "active_profile_uid": profile["uid"],
            "timeout_seconds": int(profile.get("timeout_seconds") or 90),
        }
    )
    return runtime


def run_model_comparison(conn, config, case_uid, requested_uids=None):
    profiles = _comparison_profiles(conn, config, requested_uids)
    workspace, alert, detection, evidence, _breakdown, _findings = prepare_case_context(
        conn,
        config,
        case_uid,
        assessment_type="model_comparison",
    )
    prompt = build_prompt(alert, detection, evidence)
    evidence_sha256 = text_sha256(prompt)
    run_id, comparison_uid = create_ai_comparison_run(
        conn,
        case_uid,
        workspace["detection_id"],
        evidence_sha256,
        PROMPT_VERSION,
        threat_intel_evidence=evidence.get("threat_intel") or {},
    )

    complete = 0
    errors = []
    for slot, profile in zip(("A", "B", "C"), profiles):
        try:
            report = ask_ai_model(
                _config_for_profile(config, profile),
                alert,
                detection,
                evidence_context=evidence,
            )
            insert_ai_comparison_candidate(
                conn,
                run_id,
                slot,
                profile["uid"],
                report=report,
            )
            complete += 1
        except Exception as exc:
            error = f"{type(exc).__name__}: model request failed"
            errors.append(f"{slot}: {error}")
            insert_ai_comparison_candidate(
                conn,
                run_id,
                slot,
                profile["uid"],
                error=error,
            )

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
        },
    )
    return {
        "comparison_uid": comparison_uid,
        "case_uid": case_uid,
        "status": status,
        "candidate_count": complete,
    }

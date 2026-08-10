"""Durable, sequential multi-model comparisons and controlled experiments."""

from copy import deepcopy
import json
import math
import time
from threading import Lock

import requests

from app.ai_activity import ai_activity_callback
from app.ai_client import ask_ai_model, build_prompt_audit, text_sha256
from app.case_assessment import prepare_case_context
from app.database import (
    ai_comparison_detail,
    claim_next_ai_experiment_task,
    create_ai_comparison_run,
    create_ai_experiment_run,
    finish_ai_comparison_run,
    finish_ai_experiment_result,
    get_ai_profile,
    initial_ai_request_snapshot,
    insert_ai_comparison_candidate,
    insert_app_event,
    list_ai_profiles,
    update_ai_comparison_progress,
    upsert_ai_run_audit,
    utc_now,
)
from app.security import redact_secrets


# ADVANCED RESEARCH CONTROL: these values override config.yaml for the frozen
# control request used by model comparisons. Change them only when intentionally
# starting a new experiment design, then update the methodology and tests so
# results are not mixed across different control conditions. Normal case
# analysis still uses ``ai_model.temperature`` and ``ai_model.seed``.
CONTROL_OPTIONS = {
    "temperature": 1.0,
    "seed": 64,
    "num_ctx": 8192,
    "num_predict": 1024,
}
MISSING_MARKER = "[not provided for experiment]"
_comparison_lock = Lock()  # Legacy import compatibility; queue state lives in SQLite.


def anonymous_label(index):
    """Return stable, sortable labels for any practical candidate count."""
    return f"R{int(index) + 1:02d}"


def _comparison_profiles(conn, config, requested_uids=None):
    """Resolve a dynamic ordered list of active profiles."""
    configured = (
        requested_uids
        or config.get("ai_comparison", {}).get("profile_uids")
        or [row["uid"] for row in list_ai_profiles(conn) if row["status"] == "active"]
    )
    uids = []
    for uid in configured:
        if uid and uid not in uids:
            uids.append(uid)
    if not uids:
        raise ValueError("Select at least one active AI profile")
    profiles = []
    for uid in uids:
        profile = get_ai_profile(conn, uid)
        if not profile:
            raise ValueError(f"AI profile {uid} was not found")
        if profile.get("status") != "active":
            raise ValueError(f"AI profile {uid} is inactive")
        profiles.append(profile)
    return profiles


def _config_for_profile(config, profile, options=None):
    """Build an isolated request config for one saved AI profile.

    ``CONTROL_OPTIONS`` override normal config.yaml values. Explicit ``options``
    override both, which is how a queued experiment varies temperature or seed
    without changing application-wide settings.
    """
    runtime = deepcopy(config)
    ai_model = runtime.setdefault("ai_model", {})
    ai_model.update(
        {
            "host": profile["host"],
            "model": profile["model"],
            "provider": profile["provider"],
            "active_profile_uid": profile["uid"],
            "timeout_seconds": int(profile.get("timeout_seconds") or 90),
            **CONTROL_OPTIONS,
            **(options or {}),
        }
    )
    return runtime


def _tags_for_host(host, timeout=10):
    """Fetch the model inventory advertised by an Ollama-compatible endpoint."""
    response = requests.get(f"{str(host).rstrip('/')}/api/tags", timeout=timeout)
    response.raise_for_status()
    return response.json().get("models") or []


def capture_model_inventory(profiles):
    """Capture Ollama model details once when a baseline is queued."""
    by_host = {}
    inventory = {}
    for profile in profiles:
        host = str(profile["host"]).rstrip("/")
        if host not in by_host:
            by_host[host] = _tags_for_host(host)
        model = next(
            (
                item
                for item in by_host[host]
                if item.get("name") == profile["model"]
                or item.get("model") == profile["model"]
            ),
            None,
        )
        if not model:
            raise ValueError(
                f"Model {profile['model']} was not returned by {host}/api/tags"
            )
        details = model.get("details") or {}
        inventory[profile["uid"]] = {
            "profile_uid": profile["uid"],
            "provider": profile["provider"],
            "model": profile["model"],
            "digest": model.get("digest"),
            "size": model.get("size"),
            "quantization": details.get("quantization_level"),
            "details": details,
        }
    return inventory


def _snapshot_for_case(conn, config, case_uid, profiles):
    """Freeze the exact prompt and evidence shared by comparison candidates."""
    workspace, alert, detection, evidence, _findings = prepare_case_context(
        conn, config, case_uid, assessment_type="model_comparison"
    )
    snapshot = initial_ai_request_snapshot(conn, workspace["detection_id"])
    if not snapshot:
        _prompt, audit = build_prompt_audit(
            _config_for_profile(config, profiles[0]), alert, detection, evidence
        )
        snapshot = {
            "prompt_text": audit["audit_prompt_text"],
            "prompt_sha256": audit["prompt_sha256"],
            "prompt_version": audit["prompt_version"],
            "evidence_package": audit["audit_evidence_package"],
            "evidence_sha256": audit["audit_evidence_sha256"],
            "evidence_manifest": audit["audit_evidence_manifest"],
            "omission_manifest": audit["audit_omissions"],
            "source_map": audit["audit_source_map"],
            "request_options": {
                "stream": False,
                "options": dict(CONTROL_OPTIONS),
            },
        }
    return workspace, alert, detection, evidence, snapshot


def queue_model_comparison(
    conn, config, case_uid, requested_uids=None, inventory_loader=None
):
    """Freeze a baseline and return immediately with a queued comparison UID."""
    profiles = _comparison_profiles(conn, config, requested_uids)
    workspace, _alert, _detection, _evidence, snapshot = _snapshot_for_case(
        conn, config, case_uid, profiles
    )
    inventory = (inventory_loader or capture_model_inventory)(profiles)
    stored_context = (
        (snapshot.get("evidence_package") or {}).get("evidence_context") or {}
    )
    _run_id, comparison_uid = create_ai_comparison_run(
        conn,
        case_uid,
        workspace["detection_id"],
        snapshot["evidence_sha256"],
        snapshot["prompt_version"],
        threat_intel_evidence=stored_context.get("threat_intel") or {},
        selected_profile_uids=[profile["uid"] for profile in profiles],
        control_snapshot=snapshot,
        model_inventory=inventory,
        status="queued",
    )
    insert_app_event(
        conn,
        "info",
        "ai_comparison",
        f"Queued model comparison {comparison_uid}",
        {"case_uid": case_uid, "expected_candidates": len(profiles)},
    )
    return {
        "comparison_uid": comparison_uid,
        "case_uid": case_uid,
        "status": "queued",
        "expected_candidate_count": len(profiles),
    }


def _run_snapshot(conn, comparison_uid):
    """Load and decode one durable comparison run from SQLite."""
    row = conn.execute(
        """
        SELECT * FROM ai_comparison_runs WHERE comparison_uid = ?
        """,
        (comparison_uid,),
    ).fetchone()
    if not row:
        raise ValueError("Comparison was not found")
    item = dict(row)
    for source, target, fallback in (
        ("selected_profile_uids_json", "selected_profile_uids", []),
        ("model_inventory_json", "model_inventory", {}),
        ("evidence_package_json", "evidence_package", {}),
        ("evidence_manifest_json", "evidence_manifest", {}),
        ("omission_manifest_json", "omission_manifest", []),
        ("source_map_json", "source_map", {}),
        ("control_request_options_json", "request_options", {}),
    ):
        item[target] = json.loads(item.pop(source) or json.dumps(fallback))
    return item


def process_comparison_run(conn, config, comparison_uid):
    """Execute every remaining candidate sequentially from the frozen control."""
    run = _run_snapshot(conn, comparison_uid)
    if run["status"] in {"complete", "partial", "failed", "cancelled"}:
        return ai_comparison_detail(conn, comparison_uid)
    claimed = conn.execute(
        """
        UPDATE ai_comparison_runs
        SET status = 'running', worker_claimed_at = ?
        WHERE id = ? AND status = 'queued'
        """,
        (utc_now(), run["id"]),
    ).rowcount
    conn.commit()
    if run["status"] == "queued" and claimed != 1:
        return None

    existing = {
        row["ai_profile_uid"]
        for row in conn.execute(
            "SELECT ai_profile_uid FROM ai_comparison_candidates WHERE comparison_run_id = ?",
            (run["id"],),
        ).fetchall()
    }
    errors = []
    snapshot = {
        "prompt_text": run["prompt_text"],
        "prompt_sha256": run["prompt_sha256"],
        "prompt_version": run["prompt_version"],
        "evidence_package": run["evidence_package"],
        "evidence_sha256": run["evidence_sha256"],
        "evidence_manifest": run["evidence_manifest"],
        "omission_manifest": run["omission_manifest"],
        "source_map": run["source_map"],
        "request_options": run["request_options"],
    }
    alert = (run["evidence_package"].get("event_context") or {}).copy()
    for index, profile_uid in enumerate(run["selected_profile_uids"]):
        if profile_uid in existing:
            continue
        slot = anonymous_label(index)
        profile = get_ai_profile(conn, profile_uid)
        inventory = run["model_inventory"].get(profile_uid) or {}
        try:
            if not profile or profile.get("status") != "active":
                raise ValueError(f"AI profile {profile_uid} is unavailable")
            if inventory.get("digest"):
                _verify_current_digest(profile, inventory["digest"])
            _activity_uid, progress = ai_activity_callback(
                conn,
                config,
                "model_comparison",
                case_uid=run["case_uid"],
                detection_id=run["detection_id"],
                comparison_uid=comparison_uid,
                anonymous_slot=slot,
            )
            report = ask_ai_model(
                _config_for_profile(config, profile),
                alert,
                {},
                progress_callback=progress,
                prepared_request=snapshot,
            )
            report.update(
                {
                    "model_digest": inventory.get("digest"),
                    "model_size": inventory.get("size"),
                    "model_quantization": inventory.get("quantization"),
                }
            )
            insert_ai_comparison_candidate(
                conn, run["id"], slot, profile_uid, report=report
            )
            upsert_ai_run_audit(
                conn,
                run["detection_id"],
                report,
                assessment_type=f"model_comparison_{slot.lower()}",
            )
        except Exception as exc:
            error = redact_secrets(str(exc), config)
            errors.append(f"{slot}: {error}")
            insert_ai_comparison_candidate(
                conn,
                run["id"],
                slot,
                profile_uid,
                report={
                    "model_provider": (profile or {}).get("provider"),
                    "model_name": (profile or {}).get("model"),
                    "model_identity": (
                        f"{profile.get('provider')}:{profile.get('model')}"
                        if profile
                        else None
                    ),
                    "model_digest": inventory.get("digest"),
                },
                error=error,
            )
        update_ai_comparison_progress(conn, run["id"])

    counts = update_ai_comparison_progress(conn, run["id"])
    expected = int(run["expected_candidate_count"])
    status = (
        "complete"
        if counts["completed"] == expected
        else "partial"
        if counts["completed"]
        else "failed"
    )
    finish_ai_comparison_run(
        conn, run["id"], status, counts["completed"], "; ".join(errors) or None
    )
    return ai_comparison_detail(conn, comparison_uid)


def process_next_comparison(conn, config):
    """Atomically claim and process the oldest queued model comparison."""
    # Claim under a write transaction. Stale work is recoverable after a
    # stopped worker, while active runs refresh worker_claimed_at per result.
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute(
            """
            UPDATE ai_comparison_runs
            SET status = 'queued', worker_claimed_at = NULL
            WHERE status = 'running'
              AND datetime(worker_claimed_at) < datetime('now', '-10 minutes')
            """
        )
        row = conn.execute(
            """
            SELECT id, comparison_uid FROM ai_comparison_runs
            WHERE status = 'queued' ORDER BY id LIMIT 1
            """
        ).fetchone()
        if row:
            conn.execute(
                """
                UPDATE ai_comparison_runs
                SET status = 'running', worker_claimed_at = ?
                WHERE id = ? AND status = 'queued'
                """,
                (utc_now(), row["id"]),
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return process_comparison_run(conn, config, row["comparison_uid"]) if row else None


def run_model_comparison(conn, config, case_uid, requested_uids=None):
    """Compatibility helper: queue and process one baseline synchronously."""
    queued = queue_model_comparison(
        conn,
        config,
        case_uid,
        requested_uids,
        inventory_loader=lambda profiles: {
            profile["uid"]: {
                "profile_uid": profile["uid"],
                "provider": profile["provider"],
                "model": profile["model"],
            }
            for profile in profiles
        },
    )
    return process_comparison_run(conn, config, queued["comparison_uid"])


def _baseline_candidates(conn, comparison_uid, successful_only=True):
    """Return candidate responses eligible to become experiment controls."""
    query = """
        SELECT candidates.*, runs.case_uid, runs.detection_id,
               runs.prompt_text AS control_prompt_text,
               runs.prompt_sha256 AS control_prompt_sha256,
               runs.evidence_package_json AS control_evidence_package_json,
               runs.evidence_sha256 AS control_evidence_sha256,
               runs.prompt_version AS control_prompt_version,
               runs.model_inventory_json
        FROM ai_comparison_candidates AS candidates
        JOIN ai_comparison_runs AS runs ON runs.id = candidates.comparison_run_id
        WHERE runs.comparison_uid = ?
    """
    if successful_only:
        query += " AND candidates.status = 'complete'"
    return [dict(row) for row in conn.execute(query, (comparison_uid,)).fetchall()]


def _verify_current_digest(profile, expected_digest):
    """Verify that the served model binary matches the queued baseline digest."""
    inventory = capture_model_inventory([profile])[profile["uid"]]
    if expected_digest and inventory.get("digest") != expected_digest:
        raise ValueError(
            f"Model digest changed for {profile['model']}; create a new baseline comparison"
        )
    return inventory


def queue_stability_experiment(conn, config, comparison_uid, settings):
    """Queue temperature/seed variants against the analyst-selected response."""
    winner = _selected_winner(conn, comparison_uid)
    if not winner:
        raise ValueError("Experiment requires a reviewed baseline with one winner")
    normalized = []
    seen = set()
    for row in settings:
        temperature = float(row["temperature"])
        seed = int(row["seed"])
        if not math.isfinite(temperature) or temperature < 0:
            raise ValueError("Temperature must be a finite non-negative number")
        key = (temperature, seed)
        if key in seen:
            raise ValueError("Duplicate temperature and seed combinations are not allowed")
        seen.add(key)
        normalized.append(
            {
                "label": str(row.get("label") or f"temperature {temperature}, seed {seed}"),
                "temperature": temperature,
                "seed": seed,
            }
        )
    if not normalized:
        raise ValueError("Add at least one temperature and seed combination")
    inventory_map = json.loads(winner.get("model_inventory_json") or "{}")
    profile = get_ai_profile(conn, winner["ai_profile_uid"])
    if not profile:
        raise ValueError("The selected baseline profile is no longer available")
    inventory = _verify_current_digest(
        profile,
        winner.get("model_digest")
        or (inventory_map.get(profile["uid"]) or {}).get("digest"),
    )
    tasks = []
    for setting in normalized:
        tasks.append(
            {
                "baseline_candidate_id": winner["id"],
                "ai_profile_uid": profile["uid"],
                "anonymous_label": winner["anonymous_slot"],
                "model_provider": profile["provider"],
                "model_name": profile["model"],
                "model_identity": winner["model_identity"],
                "model_digest": inventory.get("digest"),
                "model_size": inventory.get("size"),
                "model_quantization": inventory.get("quantization"),
                "variant_label": setting["label"],
                "temperature": setting["temperature"],
                "seed": setting["seed"],
                "parent_prompt_sha256": winner["prompt_sha256"],
                "parent_evidence_sha256": winner["evidence_sha256"],
                "parent_response_sha256": winner["response_sha256"],
            }
        )
    return create_ai_experiment_run(
        conn,
        "sampling_stability",
        comparison_uid,
        winner["case_uid"],
        winner["detection_id"],
        {"settings": normalized},
        tasks,
        parent_winner_candidate_id=winner["id"],
    )


def _selected_winner(conn, comparison_uid):
    """Load the successful candidate selected by the analyst for experiments."""
    row = conn.execute(
        """
        SELECT candidates.*, runs.case_uid, runs.detection_id,
               runs.prompt_text AS control_prompt_text,
               runs.prompt_sha256 AS control_prompt_sha256,
               runs.evidence_package_json AS control_evidence_package_json,
               runs.evidence_sha256 AS control_evidence_sha256,
               runs.prompt_version AS control_prompt_version,
               runs.model_inventory_json
        FROM ai_comparison_runs AS runs
        JOIN ai_comparison_votes AS votes ON votes.comparison_run_id = runs.id
        JOIN ai_comparison_candidates AS candidates
          ON candidates.comparison_run_id = runs.id
         AND candidates.anonymous_slot = votes.selection
         AND candidates.status = 'complete'
        WHERE runs.comparison_uid = ?
        """,
        (comparison_uid,),
    ).fetchone()
    return dict(row) if row else None


def queue_missing_evidence_experiment(conn, config, comparison_uid, variants):
    """Queue evidence-removal variants from an analyst-selected baseline."""
    winner = _selected_winner(conn, comparison_uid)
    if not winner:
        raise ValueError("Experiment requires a reviewed baseline with one winner")
    profile = get_ai_profile(conn, winner["ai_profile_uid"])
    inventory_map = json.loads(winner.get("model_inventory_json") or "{}")
    inventory = _verify_current_digest(
        profile,
        winner.get("model_digest")
        or (inventory_map.get(profile["uid"]) or {}).get("digest"),
    )
    tasks = []
    for index, variant in enumerate(variants):
        mask = sorted({str(item) for item in variant.get("mask") or []})
        if not mask:
            raise ValueError("Each missing-evidence variant must remove evidence")
        tasks.append(
            {
                "baseline_candidate_id": winner["id"],
                "ai_profile_uid": profile["uid"],
                "anonymous_label": winner["anonymous_slot"],
                "model_provider": profile["provider"],
                "model_name": profile["model"],
                "model_identity": winner["model_identity"],
                "model_digest": inventory.get("digest"),
                "model_size": inventory.get("size"),
                "model_quantization": inventory.get("quantization"),
                "variant_label": str(variant.get("label") or f"Variant {index + 1}"),
                "temperature": 0.0,
                "seed": 42,
                "evidence_mask": mask,
                "parent_prompt_sha256": winner["prompt_sha256"],
                "parent_evidence_sha256": winner["evidence_sha256"],
                "parent_response_sha256": winner["response_sha256"],
            }
        )
    return create_ai_experiment_run(
        conn,
        "missing_evidence",
        comparison_uid,
        winner["case_uid"],
        winner["detection_id"],
        {"variants": variants},
        tasks,
        parent_winner_candidate_id=winner["id"],
    )


def mask_evidence_package(package, masks):
    """Apply consistent, explicit evidence removals to a frozen package copy."""
    masked = deepcopy(package)
    masks = set(masks)
    event = masked.get("event_context") or {}
    evidence = masked.get("evidence_context") or {}
    fusion = (evidence.get("sensor_fusion") or {})
    findings = fusion.get("findings") or []
    source_value = event.get("src_ip")
    destination_value = event.get("dest_ip")

    def replace_scalar(value, target):
        """Replace every exact occurrence of one observable with a marker."""
        if isinstance(value, dict):
            return {key: replace_scalar(child, target) for key, child in value.items()}
        if isinstance(value, list):
            return [replace_scalar(child, target) for child in value]
        return MISSING_MARKER if target and str(value) == str(target) else value

    def remove_named_context(value, key_fragment, sensor_name=None):
        """Recursively mask fields or sensor findings matching one context name."""
        if isinstance(value, dict):
            cleaned = {}
            for key, child in value.items():
                if key_fragment in str(key).lower():
                    cleaned[key] = {"status": "not_provided_for_experiment"}
                    continue
                if sensor_name and str(value.get("sensor") or "").lower() == sensor_name:
                    return {"status": "not_provided_for_experiment"}
                cleaned[key] = remove_named_context(child, key_fragment, sensor_name)
            return cleaned
        if isinstance(value, list):
            return [
                remove_named_context(child, key_fragment, sensor_name)
                for child in value
                if not (
                    sensor_name
                    and isinstance(child, dict)
                    and str(child.get("sensor") or "").lower() == sensor_name
                )
            ]
        return value

    if "source_ip" in masks:
        masked = replace_scalar(masked, source_value)
        masked.setdefault("event_context", {})["src_ip"] = MISSING_MARKER
    if "destination_ip" in masks:
        masked = replace_scalar(masked, destination_value)
        masked.setdefault("event_context", {})["dest_ip"] = MISSING_MARKER
    if "ports" in masks:
        for key in ("src_port", "dest_port"):
            masked.setdefault("event_context", {})[key] = MISSING_MARKER
        for finding in findings:
            finding["source_port"] = MISSING_MARKER
            finding["destination_port"] = MISSING_MARKER
    if "protocol" in masks:
        masked.setdefault("event_context", {})["protocol"] = MISSING_MARKER
        for finding in findings:
            finding["protocol"] = MISSING_MARKER
    if "zeek_context" in masks:
        masked = remove_named_context(masked, "zeek", "zeek")
        evidence = masked.get("evidence_context") or {}
        fusion = evidence.get("sensor_fusion") or {}
        findings = fusion.get("findings") or []
    if "threat_intelligence" in masks:
        masked = remove_named_context(masked, "threat_intel")
        evidence = masked.get("evidence_context") or {}
        evidence["threat_intel"] = {"status": "not_provided_for_experiment"}
    if "correlation" in masks:
        masked["correlation"] = {"status": "not_provided_for_experiment"}
    if "suricata_details" in masks:
        fusion["findings"] = [
            item
            for item in fusion.get("findings") or []
            if str(item.get("sensor")).lower() != "suricata"
        ]
        masked.setdefault("event_context", {})["signature"] = MISSING_MARKER
    masked["evidence_context"] = evidence
    masked["experiment_evidence_mask"] = {
        "status": "evidence_removed_for_experiment",
        "removed": sorted(masks),
    }
    return masked


def _variant_prompt(control_prompt, control_package, variant_package):
    """Replace only the evidence JSON inside an otherwise frozen prompt."""
    marker = "Analyze this event package:"
    marker_index = control_prompt.find(marker)
    if marker_index < 0:
        raise ValueError("Stored prompt version has no event-package boundary")
    package_start = control_prompt.find("{", marker_index + len(marker))
    if package_start < 0:
        raise ValueError("Stored prompt version has no serialized event package")
    try:
        embedded_package, consumed = json.JSONDecoder().raw_decode(
            control_prompt[package_start:]
        )
    except json.JSONDecodeError as exc:
        raise ValueError(
            "Stored prompt version contains an unreadable event package"
        ) from exc
    if embedded_package != control_package:
        raise ValueError(
            "Stored prompt event package does not match its audited evidence"
        )
    package_end = package_start + consumed
    variant_text = json.dumps(variant_package, separators=(",", ":"))
    return control_prompt[:package_start] + variant_text + control_prompt[package_end:]


def process_next_experiment_task(conn, config):
    """Claim one experiment task, execute its model request, and store output."""
    task = claim_next_ai_experiment_task(conn)
    if not task:
        return None
    baseline = conn.execute(
        """
        SELECT candidates.*, runs.prompt_text AS control_prompt_text,
               runs.evidence_package_json AS control_evidence_package_json,
               runs.prompt_version AS control_prompt_version,
               runs.evidence_manifest_json, runs.omission_manifest_json,
               runs.source_map_json, runs.control_request_options_json
        FROM ai_comparison_candidates AS candidates
        JOIN ai_comparison_runs AS runs ON runs.id = candidates.comparison_run_id
        WHERE candidates.id = ?
        """,
        (task["baseline_candidate_id"],),
    ).fetchone()
    baseline = dict(baseline)
    profile = get_ai_profile(conn, task["ai_profile_uid"])
    try:
        control_package = json.loads(
            baseline["control_evidence_package_json"] or "{}"
        )
        package = control_package
        prompt = baseline["control_prompt_text"]
        if task["experiment_type"] == "missing_evidence":
            package = mask_evidence_package(control_package, task["evidence_mask"])
            prompt = _variant_prompt(prompt, control_package, package)
        snapshot = {
            "prompt_text": prompt,
            "prompt_version": baseline["control_prompt_version"],
            "evidence_package": package,
            "evidence_manifest": json.loads(
                baseline["evidence_manifest_json"] or "{}"
            ),
            "omission_manifest": json.loads(
                baseline["omission_manifest_json"] or "[]"
            ),
            "source_map": json.loads(baseline["source_map_json"] or "{}"),
            "request_options": json.loads(
                baseline["control_request_options_json"] or "{}"
            ),
        }
        report = ask_ai_model(
            _config_for_profile(
                config,
                profile,
                {"temperature": task["temperature"], "seed": task["seed"]},
            ),
            control_package.get("event_context") or {},
            {},
            prepared_request=snapshot,
        )
        if task["experiment_type"] == "sampling_stability":
            if report["prompt_sha256"] != task["parent_prompt_sha256"]:
                raise ValueError("Experimental prompt does not match control")
            if report["audit_evidence_sha256"] != task["parent_evidence_sha256"]:
                raise ValueError("Experimental evidence does not match control")
        finish_ai_experiment_result(conn, task["id"], report=report)
    except Exception as exc:
        finish_ai_experiment_result(
            conn, task["id"], error=redact_secrets(str(exc), config)
        )
    return task["result_uid"]


def run_experiment_worker(config_path, poll_seconds=1.0):
    """Process durable comparisons and experiments until the worker stops."""
    from app.config import load_config
    from app.database import init_db

    config = load_config(config_path)
    conn = init_db(config.get("database", {}).get("path", "security_vm.db"))
    print("[+] LLM experiment worker starting", flush=True)
    try:
        while True:
            runtime = load_config(config_path)
            configured_poll = float(
                runtime.get("ai_experiments", {}).get(
                    "worker_poll_seconds", poll_seconds
                )
            )
            comparison = process_next_comparison(conn, runtime)
            experiment = process_next_experiment_task(conn, runtime)
            if not comparison and not experiment:
                time.sleep(max(0.1, configured_poll))
    finally:
        conn.close()

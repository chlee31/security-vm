import csv
import io
import ipaddress
import json
import re
from datetime import datetime, timezone


EXPERIMENT_TYPES = ("correlation", "scoring", "models", "combined")
EXPECTED_SENSORS = ("suricata", "zeek")
RELATIONSHIP_STATUSES = (
    "expected_related",
    "observed_related",
    "distractor",
    "fragment",
    "incorrect_merge",
)
EVENT_LABELS = (
    "expected_correctly_attached",
    "expected_missing",
    "unexpected_incorrectly_attached",
    "correctly_excluded",
)
REFERENCE_CLASSIFICATIONS = (
    "Safe",
    "Human Review Required",
    "High Risk",
    "Dangerous",
)
SCENARIO_UID_PATTERN = re.compile(r"^[A-Z0-9][A-Z0-9_-]{2,39}$")


def _clean_text(value, field, required=False, maximum=2000):
    text = str(value or "").strip()
    if required and not text:
        raise ValueError(f"{field} is required")
    if len(text) > maximum:
        raise ValueError(f"{field} must be {maximum} characters or fewer")
    return text


def _normalize_time(value, field):
    text = _clean_text(value, field, required=True, maximum=64)
    parsed_text = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(parsed_text)
    except ValueError as exc:
        raise ValueError(f"{field} must be an ISO-8601 date and time") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


def _normalize_ip(value, field):
    text = _clean_text(value, field, maximum=64)
    if not text:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError as exc:
        raise ValueError(f"{field} must be a valid IP address") from exc


def normalize_scenario(payload, scenario_uid=None):
    uid = _clean_text(
        scenario_uid or payload.get("scenario_uid"),
        "Scenario UID",
        required=True,
        maximum=40,
    ).upper()
    if not SCENARIO_UID_PATTERN.fullmatch(uid):
        raise ValueError(
            "Scenario UID must use 3-40 uppercase letters, numbers, hyphens, or underscores"
        )
    experiment_type = _clean_text(
        payload.get("experiment_type"),
        "Experiment type",
        required=True,
        maximum=32,
    ).lower()
    if experiment_type not in EXPERIMENT_TYPES:
        raise ValueError(
            f"Experiment type must be one of: {', '.join(EXPERIMENT_TYPES)}"
        )
    start_time = _normalize_time(payload.get("start_time"), "Start time")
    end_time = _normalize_time(payload.get("end_time"), "End time")
    if datetime.fromisoformat(end_time) < datetime.fromisoformat(start_time):
        raise ValueError("End time must not be earlier than start time")
    expected_case_count = int(payload.get("expected_case_count", 1))
    if expected_case_count < 0 or expected_case_count > 10000:
        raise ValueError("Expected case count must be between 0 and 10000")
    sensors = list(
        dict.fromkeys(
            str(sensor).strip().lower()
            for sensor in (payload.get("expected_sensors") or [])
            if str(sensor).strip()
        )
    )
    invalid_sensors = [sensor for sensor in sensors if sensor not in EXPECTED_SENSORS]
    if invalid_sensors:
        raise ValueError(f"Unsupported expected sensor: {invalid_sensors[0]}")

    def classification(field):
        value = _clean_text(payload.get(field), field.replace("_", " "), maximum=80)
        if value and value not in REFERENCE_CLASSIFICATIONS:
            raise ValueError(
                f"{field.replace('_', ' ').title()} must be a supported classification"
            )
        return value or None

    return {
        "scenario_uid": uid,
        "name": _clean_text(payload.get("name"), "Name", required=True, maximum=160),
        "experiment_type": experiment_type,
        "ground_truth_class": _clean_text(
            payload.get("ground_truth_class"),
            "Ground-truth category",
            required=True,
            maximum=160,
        ),
        "authorized_activity": payload.get("authorized_activity"),
        "attack_succeeded": payload.get("attack_succeeded"),
        "source_ip": _normalize_ip(payload.get("source_ip"), "Source IP"),
        "destination_ip": _normalize_ip(
            payload.get("destination_ip"), "Destination IP"
        ),
        "start_time": start_time,
        "end_time": end_time,
        "expected_case_count": expected_case_count,
        "expected_min_classification": classification(
            "expected_min_classification"
        ),
        "expected_max_classification": classification(
            "expected_max_classification"
        ),
        "expected_sensors": sensors,
        "notes": _clean_text(payload.get("notes"), "Notes", maximum=4000),
    }


def normalize_case_link(payload):
    case_uid = _clean_text(
        payload.get("case_uid"), "Case UID", required=True, maximum=80
    )
    relationship = _clean_text(
        payload.get("relationship_status") or "expected_related",
        "Relationship status",
        required=True,
        maximum=40,
    ).lower()
    if relationship not in RELATIONSHIP_STATUSES:
        raise ValueError(
            f"Relationship status must be one of: {', '.join(RELATIONSHIP_STATUSES)}"
        )
    return {
        "case_uid": case_uid,
        "relationship_status": relationship,
        "analyst_confirmed": bool(payload.get("analyst_confirmed")),
        "notes": _clean_text(payload.get("notes"), "Link notes", maximum=2000),
    }


def normalize_event_label(payload):
    sensor = _clean_text(
        payload.get("event_sensor"), "Event sensor", required=True, maximum=20
    ).lower()
    if sensor not in EXPECTED_SENSORS:
        raise ValueError(f"Event sensor must be one of: {', '.join(EXPECTED_SENSORS)}")
    label = _clean_text(
        payload.get("label"), "Event label", required=True, maximum=48
    ).lower()
    if label not in EVENT_LABELS:
        raise ValueError(f"Event label must be one of: {', '.join(EVENT_LABELS)}")
    expected_membership = label in {
        "expected_correctly_attached",
        "expected_missing",
    }
    actual_membership = label in {
        "expected_correctly_attached",
        "unexpected_incorrectly_attached",
    }
    return {
        "event_uid": _clean_text(
            payload.get("event_uid"), "Event UID", required=True, maximum=100
        ),
        "event_sensor": sensor,
        "actual_case_uid": _clean_text(
            payload.get("actual_case_uid"), "Actual case UID", maximum=80
        )
        or None,
        "expected_membership": expected_membership,
        "actual_membership": actual_membership,
        "label": label,
        "notes": _clean_text(payload.get("notes"), "Event notes", maximum=2000),
    }


def evaluation_bundle_csv(bundle):
    output = io.StringIO()
    fieldnames = [
        "record_type",
        "scenario_uid",
        "record_uid",
        "name",
        "category",
        "status",
        "start_time",
        "end_time",
        "case_uid",
        "event_uid",
        "sensor",
        "details_json",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for scenario in bundle.get("scenarios") or []:
        writer.writerow(
            {
                "record_type": "scenario",
                "scenario_uid": scenario.get("scenario_uid"),
                "record_uid": scenario.get("scenario_uid"),
                "name": scenario.get("name"),
                "category": scenario.get("ground_truth_class"),
                "status": scenario.get("experiment_type"),
                "start_time": scenario.get("start_time"),
                "end_time": scenario.get("end_time"),
                "details_json": json.dumps(
                    {
                        key: value
                        for key, value in scenario.items()
                        if key not in {"case_links", "event_labels"}
                    },
                    sort_keys=True,
                ),
            }
        )
        for link in scenario.get("case_links") or []:
            writer.writerow(
                {
                    "record_type": "case_link",
                    "scenario_uid": scenario.get("scenario_uid"),
                    "record_uid": link.get("case_uid"),
                    "status": link.get("relationship_status"),
                    "case_uid": link.get("case_uid"),
                    "details_json": json.dumps(link, sort_keys=True),
                }
            )
        for label in scenario.get("event_labels") or []:
            writer.writerow(
                {
                    "record_type": "event_label",
                    "scenario_uid": scenario.get("scenario_uid"),
                    "record_uid": label.get("event_uid"),
                    "status": label.get("label"),
                    "case_uid": label.get("actual_case_uid"),
                    "event_uid": label.get("event_uid"),
                    "sensor": label.get("event_sensor"),
                    "details_json": json.dumps(label, sort_keys=True),
                }
            )
    for run in bundle.get("scoring_runs") or []:
        writer.writerow(
            {
                "record_type": "scoring_run",
                "scenario_uid": run.get("scenario_uid"),
                "record_uid": run.get("run_uid"),
                "status": run.get("evaluation_type"),
                "case_uid": run.get("case_uid"),
                "details_json": json.dumps(run, sort_keys=True),
            }
        )
    for review in bundle.get("model_reviews") or []:
        writer.writerow(
            {
                "record_type": "model_review",
                "record_uid": review.get("review_uid"),
                "status": review.get("anonymous_label"),
                "details_json": json.dumps(review, sort_keys=True),
            }
        )
    return output.getvalue()

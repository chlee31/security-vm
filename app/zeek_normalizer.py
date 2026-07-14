from datetime import datetime, timezone
import json


ALERT_LIKE_LOGS = {"notice"}


def parse_zeek_timestamp(value):
    if value in (None, ""):
        return datetime.now(timezone.utc).isoformat()
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), timezone.utc).isoformat()
    text = str(value)
    try:
        return datetime.fromtimestamp(float(text), timezone.utc).isoformat()
    except ValueError:
        pass
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).isoformat()
    except ValueError:
        return text


def int_or_none(value):
    if value in (None, "", "-"):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def first_present(raw, *keys):
    for key in keys:
        value = raw.get(key)
        if value not in (None, "", "-"):
            return value
    return None


def normalize_actions(value):
    if value in (None, "", "-"):
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [part.strip() for part in str(value).split(",") if part.strip()]


def load_zeek_json_line(line):
    try:
        value = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Malformed Zeek JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError("Zeek JSON line must be an object")
    return value


def normalize_zeek_record(raw, log_type):
    log_type = str(log_type or "unknown")
    if log_type.endswith(".log"):
        log_type = log_type[:-4]
    src_ip = first_present(raw, "id.orig_h", "src_h", "src", "tx_hosts", "host")
    dest_ip = first_present(raw, "id.resp_h", "dst_h", "dst", "rx_hosts", "server_name")
    if isinstance(src_ip, list):
        src_ip = src_ip[0] if src_ip else None
    if isinstance(dest_ip, list):
        dest_ip = dest_ip[0] if dest_ip else None

    message = first_present(raw, "msg", "message", "query", "uri", "filename", "subject", "issuer")
    if not message:
        if log_type == "conn":
            message = f"{raw.get('proto', 'unknown')} connection {src_ip or '?'} -> {dest_ip or '?'}"
        elif log_type == "ssl":
            message = first_present(raw, "server_name", "subject", "issuer") or "TLS session observed"
        elif log_type == "dns":
            message = first_present(raw, "query", "qtype_name") or "DNS event observed"
        else:
            message = f"Zeek {log_type} event"

    return {
        "sensor": "zeek",
        "log_type": log_type,
        "timestamp": parse_zeek_timestamp(raw.get("ts")),
        "zeek_uid": first_present(raw, "uid", "fuid"),
        "source_ip": src_ip,
        "source_port": int_or_none(first_present(raw, "id.orig_p", "src_p")),
        "destination_ip": dest_ip,
        "destination_port": int_or_none(first_present(raw, "id.resp_p", "dst_p", "p")),
        "protocol": first_present(raw, "proto", "service", "transport_protocol"),
        "community_id": first_present(raw, "community_id", "community-id"),
        "event_name": first_present(raw, "note", "name", "event", "service", "qtype_name") or log_type,
        "message": str(message),
        "sub_message": first_present(raw, "sub", "addl", "status_msg", "method", "user_agent"),
        "actions": normalize_actions(raw.get("actions")),
        "suppress_for": raw.get("suppress_for"),
        "raw_json": raw,
        "alert_like": log_type in ALERT_LIKE_LOGS,
    }

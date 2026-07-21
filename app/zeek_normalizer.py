from datetime import datetime, timezone
import json


ALERT_LIKE_LOGS = {"notice"}

ZEEK_EVIDENCE_FIELDS = {
    "conn": (
        "service", "duration", "orig_bytes", "resp_bytes", "conn_state",
        "local_orig", "local_resp", "missed_bytes", "history",
    ),
    "dns": (
        "query", "qclass_name", "qtype_name", "rcode_name", "answers",
        "TTLs", "rejected",
    ),
    "http": (
        "method", "host", "uri", "referrer", "user_agent", "status_code",
        "status_msg", "request_body_len", "response_body_len",
    ),
    "ssl": (
        "version", "cipher", "curve", "server_name", "resumed", "established",
        "validation_status", "sni_matches_cert", "ja3", "ja3s",
    ),
    "files": (
        "fuid", "source", "filename", "mime_type", "seen_bytes", "total_bytes",
        "missing_bytes", "overflow_bytes", "md5", "sha1", "sha256",
    ),
    "notice": ("note", "msg", "sub", "actions", "suppress_for"),
    "weird": ("name", "addl", "notice", "peer"),
    "ssh": (
        "auth_success", "direction", "client", "server", "cipher_alg",
        "mac_alg", "compression_alg", "kex_alg", "host_key_alg", "host_key",
    ),
    "x509": (
        "certificate.version", "certificate.serial", "certificate.subject",
        "certificate.issuer", "certificate.not_valid_before",
        "certificate.not_valid_after", "certificate.key_alg", "certificate.sig_alg",
        "san.dns", "san.ip", "basic_constraints.ca",
    ),
}


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


def zeek_evidence_details(raw, log_type):
    """Return an allowlisted protocol summary suitable for dashboards and AI prompts."""
    if not isinstance(raw, dict):
        return {}
    result = {}
    for key in ZEEK_EVIDENCE_FIELDS.get(str(log_type or "unknown"), ("service",)):
        value = raw.get(key)
        if value in (None, "", "-"):
            continue
        if isinstance(value, list):
            result[key] = value[:20]
        elif isinstance(value, (dict, tuple, set)):
            result[key] = str(value)[:500]
        elif isinstance(value, str):
            result[key] = value[:500]
        else:
            result[key] = value
    return result


def compact_zeek_context_events(events, limit=8):
    """Select a log-diverse, allowlisted Zeek sample for an AI context window."""
    events = list(events or [])
    selected = []
    selected_ids = set()
    seen_logs = set()
    for event in events:
        log_type = event.get("log_type") or "unknown"
        if log_type in seen_logs:
            continue
        selected.append(event)
        selected_ids.add(event.get("id") or id(event))
        seen_logs.add(log_type)
        if len(selected) >= limit:
            break
    for event in events:
        event_id = event.get("id") or id(event)
        if event_id in selected_ids:
            continue
        selected.append(event)
        selected_ids.add(event_id)
        if len(selected) >= limit:
            break

    output = []
    for event in selected:
        raw = event.get("raw_json") or {}
        if not isinstance(raw, dict):
            try:
                raw = json.loads(raw)
            except (TypeError, ValueError):
                raw = {}
        log_type = event.get("log_type") or "unknown"
        output.append(
            {
                "log_type": log_type,
                "zeek_event_id": event.get("id"),
                "event_uid": event.get("event_uid"),
                "zeek_uid": event.get("zeek_uid"),
                "timestamp": event.get("timestamp"),
                "source_ip": event.get("source_ip"),
                "source_port": event.get("source_port"),
                "destination_ip": event.get("destination_ip"),
                "destination_port": event.get("destination_port"),
                "protocol": event.get("protocol"),
                "event_name": event.get("event_name"),
                "message": event.get("message"),
                "sub_message": event.get("sub_message"),
                "details": event.get("details") or zeek_evidence_details(raw, log_type),
            }
        )
    return output


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

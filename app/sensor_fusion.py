"""Convert normalized Suricata and Zeek records into one common finding shape.

The input is one normalized sensor row. The output names its sensor, source-row
ID, event UID, timestamps, endpoints, finding type/name, severity, confidence,
and Community ID in the same format regardless of source. Database correlation
uses that format to decide whether the finding starts or supports a case.

This is a link layer rather than another evidence copy: ``alerts`` and
``zeek_events`` remain authoritative, while ``sensor_findings`` records which
source rows belong to each unified ``detection``.
"""

import json

from app.normalizer import detection_type_from_alert


HIGH_CONFIDENCE_TERMS = (
    "malware",
    "exploit",
    "command and control",
    "c2",
    "port scan",
    "bruteforce",
    "brute force",
    "sql injection",
)


def zeek_notice_priority(event):
    """Translate Zeek notice text into a simple Suricata-like priority."""
    text = f"{event.get('event_name', '')} {event.get('message', '')}".lower()
    return 2 if any(term in text for term in HIGH_CONFIDENCE_TERMS) else 3


def zeek_notice_to_alert(event):
    """Adapt a Zeek notice to the case-creation fields used by the correlator.

    The historical correlator accepts an alert-shaped dictionary.  This adapter
    lets a required Zeek notice initiate a case without pretending it came from
    Suricata; the resulting sensor state and finding link still identify Zeek.
    """
    priority = zeek_notice_priority(event)
    return {
        "suricata_event_id": "",
        "timestamp": event.get("timestamp"),
        "src_ip": event.get("source_ip"),
        "dest_ip": event.get("destination_ip"),
        "src_port": event.get("source_port"),
        "dest_port": event.get("destination_port"),
        "protocol": event.get("protocol"),
        "signature": event.get("event_name") or "Zeek Notice",
        "category": event.get("message") or "Zeek policy notice",
        "severity": priority,
        "priority": priority,
        "flow_id": event.get("zeek_uid") or "",
        "community_id": event.get("community_id"),
        "raw_json": json.dumps(event.get("raw_json") or {}, separators=(",", ":")),
        "sensor_state": "zeek_only",
    }


def zeek_detection(event, single_sensor_strength=0.5):
    """Create a new Zeek-only case when no existing case can accept the notice."""
    alert = zeek_notice_to_alert(event)
    detection_type = detection_type_from_alert(alert)
    try:
        rule_strength = float(single_sensor_strength)
    except (TypeError, ValueError):
        rule_strength = 0.5
    return alert, {
        "first_alert_id": None,
        "first_seen": alert.get("timestamp"),
        "last_seen": alert.get("timestamp"),
        "src_ip": alert.get("src_ip"),
        "dest_ip": alert.get("dest_ip"),
        "src_port": alert.get("src_port"),
        "dest_port": alert.get("dest_port"),
        "protocol": alert.get("protocol"),
        "community_id": alert.get("community_id"),
        "sensor_state": "zeek_only",
        "agreement_state": "single_sensor",
        "correlation_method": "single_sensor",
        "correlation_confidence": max(0.0, min(1.0, rule_strength)),
        "detection_type": detection_type,
        "alert_count": 1,
        "unique_dest_ports": 1 if alert.get("dest_port") else 0,
        "unique_dest_hosts": 1 if alert.get("dest_ip") else 0,
        "time_window_seconds": 0,
        "status": "correlated",
    }


def suricata_finding(alert_id, alert):
    """Create the lightweight case link back to one stored Suricata alert."""
    try:
        priority = int(alert.get("priority") or 3)
    except (TypeError, ValueError):
        priority = 3
    return {
        "sensor": "suricata",
        "sensor_event_id": alert_id,
        "finding_type": "signature_alert",
        "finding_name": alert.get("signature") or "Suricata alert",
        "severity": priority,
        "confidence": 0.9 if priority <= 2 else 0.65,
        "community_id": alert.get("community_id"),
        "raw_event": alert.get("raw_json"),
    }


def zeek_finding(zeek_event_id, event):
    """Create the lightweight case link back to one stored Zeek notice."""
    priority = zeek_notice_priority(event)
    return {
        "sensor": "zeek",
        "sensor_event_id": zeek_event_id,
        "finding_type": "notice",
        "finding_name": event.get("event_name") or "Zeek notice",
        "severity": priority,
        "confidence": 0.85 if priority == 2 else 0.65,
        "community_id": event.get("community_id"),
        "raw_event": event.get("raw_json") or event,
    }

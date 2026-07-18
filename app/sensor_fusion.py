import json

from app.mitre_mapper import map_detection
from app.normalizer import detection_type_from_alert
from app.risk_score import cap_score, severity_score


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
    text = f"{event.get('event_name', '')} {event.get('message', '')}".lower()
    return 2 if any(term in text for term in HIGH_CONFIDENCE_TERMS) else 3


def zeek_notice_to_alert(event):
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
        "pcap_point": None,
        "raw_json": json.dumps(event.get("raw_json") or {}, separators=(",", ":")),
        "sensor_state": "zeek_only",
    }


def zeek_detection(event, single_sensor_strength=0.5):
    alert = zeek_notice_to_alert(event)
    detection_type = detection_type_from_alert(alert)
    mitre = map_detection(detection_type)
    notice_weight = 15 if zeek_notice_priority(event) == 2 else 8
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
        "mitre_id": mitre.get("id"),
        "mitre_name": mitre.get("name"),
        "python_initial_score": cap_score(severity_score(alert.get("priority")) + notice_weight + mitre.get("score", 0)),
        "status": "correlated",
    }


def suricata_finding(alert_id, alert):
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

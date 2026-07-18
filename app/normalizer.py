import json
import re


DETECTION_TYPE_PATTERNS = (
    (
        "port_scan",
        (
            r"\bport[ -]?scan(?:ning)?\b",
            r"\bnetwork[ -]?scan(?:ning)?\b",
            r"\bsyn[ -]?scan\b",
            r"\bnmap\b",
            r"\bmasscan\b",
            r"\bscan in progress\b",
            r"\bscanner detected\b",
        ),
    ),
    (
        "dns_tunneling",
        (
            r"\bdns[ -]?tunnel(?:ing)?\b",
            r"\bdns[ -]?exfil(?:tration)?\b",
            r"\bdns covert channel\b",
            r"\banomalous dns\b",
            r"\bexcessive dns quer(?:y|ies)\b",
            r"\bdynamic_dns query to nip\.io\b",
        ),
    ),
    (
        "beaconing",
        (
            r"\bbeacon(?:ing)?\b",
            r"\bcommand and control\b",
            r"\bc2\b",
            r"\bcnc\b",
            r"\bc2 (?:traffic|communication|callback|channel)\b",
            r"\bcallback\b",
            r"\bperiodic (?:connection|communication)\b",
        ),
    ),
    (
        "brute_force",
        (
            r"\bbrute[ -]?force\b",
            r"\bpassword guess(?:ing)?\b",
            r"\bcredential guess(?:ing)?\b",
            r"\brepeated authentication fail(?:ure|ures)\b",
            r"\bmultiple failed logins?\b",
        ),
    ),
)


def normalize_suricata_event(event):
    if event.get("event_type") != "alert":
        return None

    alert = event.get("alert", {})
    return {
        "suricata_event_id": str(event.get("event_id") or event.get("flow_id") or ""),
        "signature_id": alert.get("signature_id"),
        "timestamp": event.get("timestamp"),
        "src_ip": event.get("src_ip"),
        "dest_ip": event.get("dest_ip"),
        "src_port": event.get("src_port"),
        "dest_port": event.get("dest_port"),
        "protocol": event.get("proto"),
        "signature": alert.get("signature", "Unknown Suricata alert"),
        "category": alert.get("category", "unknown"),
        "severity": alert.get("severity"),
        "priority": alert.get("severity"),
        "flow_id": str(event.get("flow_id") or ""),
        "community_id": event.get("community_id"),
        "raw_json": json.dumps(event, separators=(",", ":")),
    }


def detection_type_from_alert(alert):
    text = f"{alert.get('signature', '')} {alert.get('category', '')}".lower()
    for detection_type, patterns in DETECTION_TYPE_PATTERNS:
        if any(re.search(pattern, text) for pattern in patterns):
            return detection_type
    return "unknown"

import json


def normalize_suricata_event(event):
    if event.get("event_type") != "alert":
        return None

    alert = event.get("alert", {})
    return {
        "suricata_event_id": str(event.get("event_id") or event.get("flow_id") or ""),
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
        "pcap_point": event.get("pcap_cnt"),
        "raw_json": json.dumps(event, separators=(",", ":")),
    }


def detection_type_from_alert(alert):
    text = f"{alert.get('signature', '')} {alert.get('category', '')}".lower()
    if "scan" in text or "syn" in text:
        return "port_scan"
    if "dns" in text or "tunnel" in text:
        return "dns_tunneling"
    if "beacon" in text or "c2" in text or "callback" in text:
        return "beaconing"
    if "brute" in text or "login" in text or "ssh" in text:
        return "brute_force"
    return "unknown"

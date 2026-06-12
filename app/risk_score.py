import ipaddress


def severity_score(priority):
    try:
        priority = int(priority)
    except (TypeError, ValueError):
        return 3
    if priority == 1:
        return 20
    if priority == 2:
        return 12
    if priority == 3:
        return 5
    return 3


def correlation_score(detection_type, alert_count, unique_ports):
    if detection_type == "port_scan":
        if unique_ports >= 50:
            return 30
        if unique_ports >= 20:
            return 20
        if unique_ports >= 10:
            return 10
    if detection_type in {"dns_tunneling", "beaconing", "brute_force"}:
        if alert_count >= 30:
            return 30
        if alert_count >= 10:
            return 20
        if alert_count >= 5:
            return 10
    return 0


def asset_direction_score(alert, config):
    dest_ip = alert.get("dest_ip")
    src_ip = alert.get("src_ip")
    assets = config.get("assets", {})

    if dest_ip in assets:
        criticality = assets[dest_ip].get("criticality", "low")
        if criticality == "critical":
            return 10
        if criticality == "high":
            return 6
        if criticality == "medium":
            return 3

    try:
        src = ipaddress.ip_address(src_ip)
        dst = ipaddress.ip_address(dest_ip)
        if src.is_private and not dst.is_private:
            return 6
    except ValueError:
        return 0

    return 0


def cap_score(score):
    return max(0, min(int(score), 100))

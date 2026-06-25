import ipaddress


def _networks(values):
    nets = []
    for value in values or []:
        try:
            nets.append(ipaddress.ip_network(value, strict=False))
        except ValueError:
            continue
    return nets


def _in_any(ip_obj, nets):
    return any(ip_obj in net for net in nets)


def classify_direction(alert, config):
    """
    Classify an alert's traffic direction relative to the lab network design.

    Returns one of:
      perimeter_ingress  - external source -> internal destination
      internal_outbound  - internal source -> external destination
      lateral            - internal source -> internal destination
      external           - external source -> external destination (rare)
      unknown            - could not parse one or both IPs
    """
    network = config.get("network", {}) if config else {}
    internal_nets = _networks(network.get("internal_subnets"))
    attacker_nets = _networks(network.get("attacker_subnets"))

    src_ip = alert.get("src_ip")
    dest_ip = alert.get("dest_ip")

    try:
        src = ipaddress.ip_address(src_ip)
        dst = ipaddress.ip_address(dest_ip)
    except (ValueError, TypeError):
        return "unknown"

    def is_internal(ip_obj):
        # Attacker subnets are explicitly external, even if RFC1918.
        if _in_any(ip_obj, attacker_nets):
            return False
        if _in_any(ip_obj, internal_nets):
            return True
        # Fall back to RFC1918 only if no internal subnets were configured.
        if not internal_nets:
            return ip_obj.is_private and not ip_obj.is_loopback
        return False

    src_internal = is_internal(src)
    dst_internal = is_internal(dst)

    if not src_internal and dst_internal:
        return "perimeter_ingress"
    if src_internal and not dst_internal:
        return "internal_outbound"
    if src_internal and dst_internal:
        return "lateral"
    return "external"


def direction_label(value):
    labels = {
        "perimeter_ingress": "Perimeter Ingress",
        "internal_outbound": "Internal Outbound",
        "lateral": "Lateral / Internal",
        "external": "External",
        "unknown": "Unknown",
    }
    return labels.get(value, "Unknown")
MITRE_MAP = {
    "port_scan": {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
    },
    "dns_tunneling": {
        "id": "T1071.004",
        "name": "Application Layer Protocol: DNS",
        "tactic": "Command and Control",
    },
    "brute_force": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
    },
    "beaconing": {
        "id": "T1071",
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
    },
    "unknown": {
        "id": None,
        "name": None,
        "tactic": None,
    },
}


def map_detection(detection_type):
    return MITRE_MAP.get(detection_type, MITRE_MAP["unknown"])

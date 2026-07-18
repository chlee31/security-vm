from app.mitre_mapper import map_detection
from app.normalizer import detection_type_from_alert
from app.risk_score import asset_direction_score, cap_python_score, severity_score


class Correlator:
    """Build the first record for a case; subsequent grouping is database-backed."""

    def __init__(self, config):
        self.config = config

    def correlate(self, alert, alert_id):
        detection_type = detection_type_from_alert(alert)
        mitre = map_detection(detection_type)
        score = (
            severity_score(alert.get("priority"))
            + asset_direction_score(alert, self.config)
        )
        strengths = self.config.get("correlation", {}).get("strengths", {})
        try:
            single_sensor_strength = float(strengths.get("single_sensor", 0.5))
        except (TypeError, ValueError):
            single_sensor_strength = 0.5
        return {
            "first_alert_id": alert_id,
            "first_seen": alert.get("timestamp"),
            "last_seen": alert.get("timestamp"),
            "src_ip": alert.get("src_ip"),
            "dest_ip": alert.get("dest_ip"),
            "src_port": alert.get("src_port"),
            "dest_port": alert.get("dest_port"),
            "protocol": alert.get("protocol"),
            "community_id": alert.get("community_id"),
            "sensor_state": alert.get("sensor_state", "suricata_only"),
            "agreement_state": "single_sensor",
            "correlation_method": "single_sensor",
            "correlation_confidence": max(0.0, min(1.0, single_sensor_strength)),
            "detection_type": detection_type,
            "alert_count": 1,
            "unique_dest_ports": 1 if alert.get("dest_port") is not None else 0,
            "unique_dest_hosts": 1 if alert.get("dest_ip") else 0,
            "time_window_seconds": 0,
            "mitre_id": mitre.get("id"),
            "mitre_name": mitre.get("name"),
            "python_initial_score": cap_python_score(score),
            "status": "developing",
        }

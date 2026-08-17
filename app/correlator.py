"""Turn the first normalized Suricata alert into a new case candidate.

``main.py`` passes this module an already normalized alert and its SQLite alert
ID. ``Correlator.correlate`` copies the endpoint, protocol, time, behavior label,
Flow ID, and Community ID into a dictionary suitable for the ``detections``
table. It does not perform the complete Suricata/Zeek join. Database correlation
later decides whether another finding joins this case or starts a different one.
"""

from app.normalizer import detection_type_from_alert


class Correlator:
    """Build the case shell used before database-backed grouping can occur."""

    def __init__(self, config):
        """Keep correlation strengths used to describe a single-sensor start."""
        self.config = config

    def correlate(self, alert, alert_id):
        """Create an ungrouped case from one already normalized alert.

        Endpoint, protocol, time, and Community ID values are copied so later
        SQL queries can compare new findings without reparsing raw JSON. The
        initial state explicitly says ``single_sensor``; fusion may update it
        after compatible Suricata or Zeek evidence arrives.
        """
        detection_type = detection_type_from_alert(alert)
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
            "status": "developing",
        }

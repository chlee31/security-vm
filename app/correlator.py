from collections import defaultdict, deque
from datetime import datetime, timezone

from app.mitre_mapper import map_detection
from app.normalizer import detection_type_from_alert
from app.risk_score import asset_direction_score, cap_score, correlation_score, severity_score


WINDOW_SECONDS = 60


class Correlator:
    def __init__(self, config):
        self.config = config
        self.events_by_src = defaultdict(lambda: deque())

    def correlate(self, alert, alert_id):
        now = datetime.now(timezone.utc)
        src_ip = alert.get("src_ip")
        queue = self.events_by_src[src_ip]
        queue.append({"time": now, "alert": alert, "alert_id": alert_id})

        while queue and (now - queue[0]["time"]).total_seconds() > WINDOW_SECONDS:
            queue.popleft()

        detection_type = detection_type_from_alert(alert)
        dest_ports = {item["alert"].get("dest_port") for item in queue if item["alert"].get("dest_port")}
        dest_hosts = {item["alert"].get("dest_ip") for item in queue if item["alert"].get("dest_ip")}
        mitre = map_detection(detection_type)

        score = (
            severity_score(alert.get("priority"))
            + correlation_score(detection_type, len(queue), len(dest_ports))
            + mitre.get("score", 0)
            + asset_direction_score(alert, self.config)
        )

        return {
            "first_alert_id": queue[0]["alert_id"],
            "first_seen": queue[0]["alert"].get("timestamp"),
            "last_seen": alert.get("timestamp"),
            "src_ip": src_ip,
            "dest_ip": alert.get("dest_ip"),
            "detection_type": detection_type,
            "alert_count": len(queue),
            "unique_dest_ports": len(dest_ports),
            "unique_dest_hosts": len(dest_hosts),
            "time_window_seconds": WINDOW_SECONDS,
            "mitre_id": mitre.get("id"),
            "mitre_name": mitre.get("name"),
            "python_initial_score": cap_score(score),
            "status": "correlated",
        }

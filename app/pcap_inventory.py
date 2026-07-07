from datetime import datetime, timedelta, timezone
from pathlib import Path


def parse_event_time(value):
    if not value:
        return None
    text = str(value)
    normalized = text.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalized).astimezone(timezone.utc)
    except ValueError:
        pass
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(text, fmt).astimezone(timezone.utc)
        except ValueError:
            continue
    return None


def file_label(path):
    name = path.name.lower()
    if "external" in name:
        return "external"
    if "internal" in name:
        return "internal"
    return "capture"


def list_pcap_files(config, start_time=None, end_time=None):
    pcap_config = config.get("pcap", {})
    rolling_dir = Path(pcap_config.get("rolling_dir", "/var/log/pcap"))
    window_minutes = int(pcap_config.get("incident_window_minutes", 5))
    start = parse_event_time(start_time)
    end = parse_event_time(end_time)

    if start:
        start -= timedelta(minutes=window_minutes)
    if end:
        end += timedelta(minutes=window_minutes)

    if not rolling_dir.exists():
        return {
            "directory": str(rolling_dir),
            "status": "missing_directory",
            "files": [],
        }

    files = []
    for path in sorted(rolling_dir.glob("*.pcap*")):
        try:
            stat = path.stat()
        except OSError:
            continue

        modified = datetime.fromtimestamp(stat.st_mtime, timezone.utc)
        related = True
        if start and modified < start:
            related = False
        if end and modified > end:
            related = False

        files.append(
            {
                "name": path.name,
                "path": str(path),
                "label": file_label(path),
                "size_bytes": stat.st_size,
                "modified_at": modified.isoformat(),
                "related": related,
            }
        )

    return {
        "directory": str(rolling_dir),
        "status": "ok",
        "window_minutes": window_minutes,
        "files": files,
    }

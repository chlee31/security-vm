from pathlib import Path
import time

from app.database import (
    get_zeek_checkpoint,
    insert_app_event,
    insert_zeek_event,
    upsert_zeek_checkpoint,
    zeek_event_id,
)
from app.zeek_normalizer import load_zeek_json_line, normalize_zeek_record


def zeek_log_path(config, log_type):
    directory = Path(config.get("zeek", {}).get("log_directory", "/opt/zeek/logs/current"))
    return directory / f"{log_type}.log"


def enabled_log_types(config):
    zeek_config = config.get("zeek", {})
    logs = zeek_config.get("context_logs") or ["notice", "weird"]
    if not zeek_config.get("ingest_notice", True):
        logs = [item for item in logs if item != "notice"]
    if not zeek_config.get("ingest_weird", True):
        logs = [item for item in logs if item != "weird"]
    return logs


class ZeekLogFollower:
    def __init__(self, conn, config, log_type, on_event=None):
        self.conn = conn
        self.config = config
        self.log_type = log_type
        self.path = zeek_log_path(config, log_type)
        self.handle = None
        self.inode = None
        self.last_access_error = ""
        self.on_event = on_event

    def close(self):
        if self.handle:
            self.handle.close()
            self.handle = None

    def open_if_ready(self):
        try:
            stat = self.path.stat()
        except FileNotFoundError:
            self.close()
            self.last_access_error = ""
            return False
        except OSError as exc:
            self.close()
            message = str(exc)
            if message != self.last_access_error:
                insert_app_event(
                    self.conn,
                    "error",
                    "zeek",
                    f"Cannot access Zeek {self.log_type}.log",
                    {"path": str(self.path), "error": message},
                )
                self.last_access_error = message
            return False
        self.last_access_error = ""
        checkpoint = get_zeek_checkpoint(self.conn, self.log_type)
        if self.handle and self.inode == stat.st_ino:
            return True
        self.close()
        try:
            self.handle = self.path.open("r", encoding="utf-8", errors="replace")
        except OSError as exc:
            message = str(exc)
            if message != self.last_access_error:
                insert_app_event(
                    self.conn,
                    "error",
                    "zeek",
                    f"Cannot open Zeek {self.log_type}.log",
                    {"path": str(self.path), "error": message},
                )
                self.last_access_error = message
            return False
        self.inode = stat.st_ino
        if checkpoint and checkpoint.get("path") == str(self.path) and int(checkpoint.get("inode") or 0) == self.inode:
            self.handle.seek(int(checkpoint.get("offset") or 0))
        else:
            self.handle.seek(0)
        return True

    def poll(self):
        if not self.open_if_ready():
            return 0
        inserted = 0
        while True:
            line = self.handle.readline()
            if not line:
                break
            offset = self.handle.tell()
            line = line.strip()
            if not line:
                upsert_zeek_checkpoint(self.conn, self.log_type, self.path, self.inode, offset)
                continue
            try:
                raw = load_zeek_json_line(line)
                event = normalize_zeek_record(raw, self.log_type)
                was_inserted = insert_zeek_event(self.conn, event)
                inserted += was_inserted
                if self.on_event:
                    event_id = zeek_event_id(self.conn, event)
                    if event_id:
                        try:
                            self.on_event(event_id, event)
                        except Exception as exc:
                            insert_app_event(
                                self.conn,
                                "error",
                                "sensor_fusion",
                                f"Zeek {self.log_type} event pipeline failed: {exc}",
                                {"zeek_event_id": event_id},
                            )
            except ValueError as exc:
                insert_app_event(
                    self.conn,
                    "warning",
                    "zeek",
                    f"Malformed Zeek {self.log_type}.log line skipped",
                    {"path": str(self.path), "error": str(exc), "offset": offset},
                )
            finally:
                upsert_zeek_checkpoint(self.conn, self.log_type, self.path, self.inode, offset)
        return inserted


def run_zeek_ingest_loop(conn, config, poll_seconds=1, on_event=None):
    followers = [ZeekLogFollower(conn, config, log_type, on_event=on_event) for log_type in enabled_log_types(config)]
    insert_app_event(
        conn,
        "info",
        "zeek",
        "Zeek ingestion starting",
        {"log_types": [follower.log_type for follower in followers], "directory": config.get("zeek", {}).get("log_directory")},
    )
    try:
        while True:
            for follower in followers:
                follower.poll()
            time.sleep(poll_seconds)
    finally:
        for follower in followers:
            follower.close()

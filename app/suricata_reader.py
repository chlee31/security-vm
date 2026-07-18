import json
import os
import time
from dataclasses import dataclass
from pathlib import Path

from app.database import get_suricata_checkpoint, upsert_suricata_checkpoint


def permission_help(path):
    return (
        f"Cannot read Suricata EVE JSON at {path}. "
        "Make sure this terminal has the suricata group loaded with `groups`, "
        "then run `newgrp suricata` or log out and back in. "
        "If the file still fails, grant read access with: "
        f"sudo setfacl -m u:$USER:rx {path.parent} && sudo setfacl -m u:$USER:r {path}"
    )


@dataclass
class SuricataRecord:
    event: dict
    path: Path
    inode: int
    offset: int
    conn: object = None
    source: str = "eve"
    acknowledged: bool = False

    def acknowledge(self):
        if self.acknowledged:
            return
        if self.conn is not None:
            upsert_suricata_checkpoint(
                self.conn,
                self.path,
                self.inode,
                self.offset,
                source=self.source,
            )
        self.acknowledged = True


class SuricataEveFollower:
    def __init__(self, path, conn=None, source="eve", start_position="end", poll_seconds=0.5):
        self.path = Path(path)
        self.conn = conn
        self.source = source
        self.start_position = "beginning" if start_position == "beginning" else "end"
        self.poll_seconds = poll_seconds
        self.handle = None
        self.inode = None

    def close(self):
        if self.handle:
            self.handle.close()
            self.handle = None
        self.inode = None

    def _checkpoint(self):
        if self.conn is None:
            return None
        return get_suricata_checkpoint(self.conn, self.source)

    def open_if_ready(self):
        try:
            stat = self.path.stat()
        except FileNotFoundError:
            self.close()
            return False
        except PermissionError as exc:
            self.close()
            raise PermissionError(permission_help(self.path)) from exc

        if self.handle and self.inode == stat.st_ino:
            return True

        self.close()
        try:
            self.handle = self.path.open("r", encoding="utf-8", errors="ignore")
        except PermissionError as exc:
            raise PermissionError(permission_help(self.path)) from exc
        self.inode = stat.st_ino

        checkpoint = self._checkpoint()
        same_path_checkpoint = checkpoint and checkpoint.get("path") == str(self.path)
        if (
            same_path_checkpoint
            and int(checkpoint.get("inode") or 0) == self.inode
            and 0 <= int(checkpoint.get("offset") or 0) <= stat.st_size
        ):
            position = int(checkpoint.get("offset") or 0)
        elif same_path_checkpoint:
            # A different inode or a shorter same-inode file indicates rotation
            # or truncation. The replacement file must be read from its start.
            position = 0
        elif self.start_position == "beginning":
            position = 0
        else:
            position = stat.st_size

        self.handle.seek(position, os.SEEK_SET)
        if self.conn is not None:
            upsert_suricata_checkpoint(
                self.conn,
                self.path,
                self.inode,
                position,
                source=self.source,
            )
        return True

    def rotated_or_truncated(self):
        if not self.handle:
            return False
        try:
            stat = self.path.stat()
        except FileNotFoundError:
            return False
        except PermissionError as exc:
            raise PermissionError(permission_help(self.path)) from exc
        return stat.st_ino != self.inode or stat.st_size < self.handle.tell()

    def records(self):
        announced_wait = False
        announced_read = False
        try:
            while True:
                if not self.open_if_ready():
                    if not announced_wait:
                        print(f"[!] Waiting for Suricata EVE JSON file: {self.path}")
                        announced_wait = True
                    time.sleep(max(0.1, self.poll_seconds))
                    continue
                announced_wait = False
                if not announced_read:
                    print(f"[+] Reading Suricata EVE JSON from {self.path}")
                    announced_read = True

                line = self.handle.readline()
                if not line:
                    if self.rotated_or_truncated():
                        self.close()
                        announced_read = False
                        continue
                    time.sleep(max(0.1, self.poll_seconds))
                    continue

                offset = self.handle.tell()
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    if self.conn is not None:
                        upsert_suricata_checkpoint(
                            self.conn,
                            self.path,
                            self.inode,
                            offset,
                            source=self.source,
                        )
                    continue
                yield SuricataRecord(
                    event=event,
                    path=self.path,
                    inode=self.inode,
                    offset=offset,
                    conn=self.conn,
                    source=self.source,
                )
        finally:
            self.close()


def follow_file(path, conn=None, source="eve", start_position="end", poll_seconds=0.5):
    follower = SuricataEveFollower(
        path,
        conn=conn,
        source=source,
        start_position=start_position,
        poll_seconds=poll_seconds,
    )
    yield from follower.records()

import json
import os
import time
from pathlib import Path


def permission_help(path):
    return (
        f"Cannot read Suricata EVE JSON at {path}. "
        "Make sure this terminal has the suricata group loaded with `groups`, "
        "then run `newgrp suricata` or log out and back in. "
        "If the file still fails, grant read access with: "
        f"sudo setfacl -m u:$USER:rx {path.parent} && sudo setfacl -m u:$USER:r {path}"
    )


def follow_file(path):
    path = Path(path)
    while True:
        try:
            if path.exists():
                break
        except PermissionError as exc:
            raise PermissionError(permission_help(path)) from exc
        print(f"[!] Waiting for Suricata EVE JSON file: {path}")
        time.sleep(2)

    try:
        handle = path.open("r", encoding="utf-8", errors="ignore")
    except PermissionError as exc:
        raise PermissionError(permission_help(path)) from exc

    with handle:
        handle.seek(0, os.SEEK_END)
        print(f"[+] Reading Suricata EVE JSON from {path}")
        while True:
            line = handle.readline()
            if not line:
                time.sleep(0.5)
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue

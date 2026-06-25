import json
import os
import time
from pathlib import Path


def follow_file(path):
    path = Path(path)
    while not path.exists():
        print(f"[!] Waiting for Suricata EVE JSON file: {path}")
        time.sleep(2)

    with path.open("r", encoding="utf-8", errors="ignore") as handle:
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

from pathlib import Path
import os
import shutil
import subprocess


ZEEK_BINARY_CANDIDATES = {
    "zeek": ["zeek", "/usr/bin/zeek", "/usr/local/bin/zeek", "/opt/zeek/bin/zeek"],
    "zeekctl": ["zeekctl", "/usr/bin/zeekctl", "/usr/local/bin/zeekctl", "/opt/zeek/bin/zeekctl"],
    "zkg": ["zkg", "/usr/bin/zkg", "/usr/local/bin/zkg", "/opt/zeek/bin/zkg"],
}


def resolve_binary(name):
    for candidate in ZEEK_BINARY_CANDIDATES.get(name, [name]):
        path = shutil.which(candidate) if "/" not in candidate else candidate
        if path and Path(path).exists():
            return str(path)
    return ""


def run_command(command, timeout=8):
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError as exc:
        return {"ok": False, "returncode": 127, "stdout": "", "stderr": str(exc)}
    except subprocess.TimeoutExpired as exc:
        return {"ok": False, "returncode": 124, "stdout": exc.stdout or "", "stderr": str(exc)}
    return {
        "ok": result.returncode == 0,
        "returncode": result.returncode,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }


def log_file_status(path):
    try:
        stat = path.stat()
    except FileNotFoundError:
        return {"exists": False, "accessible": True, "size_bytes": 0, "error": ""}
    except PermissionError as exc:
        return {"exists": False, "accessible": False, "size_bytes": 0, "error": str(exc)}
    except OSError as exc:
        return {"exists": False, "accessible": False, "size_bytes": 0, "error": str(exc)}
    return {"exists": True, "accessible": True, "size_bytes": stat.st_size, "error": ""}


def running_zeek_pids(zeekctl_path):
    if not zeekctl_path:
        return []
    spool_directory = Path(zeekctl_path).resolve().parent.parent / "spool"
    try:
        pid_paths = list(spool_directory.glob("*/.pid"))
    except OSError:
        return []
    running = []
    for pid_path in pid_paths:
        try:
            pid = int(pid_path.read_text(encoding="utf-8").strip())
            os.kill(pid, 0)
            cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\x00", b" ").decode("utf-8", "replace")
        except (FileNotFoundError, PermissionError, ProcessLookupError, ValueError, OSError):
            continue
        if "zeek" in cmdline.lower():
            running.append(pid)
    return running


def zeek_status(config):
    zeek_config = config.get("zeek", {})
    zeek = resolve_binary("zeek")
    zeekctl = resolve_binary("zeekctl")
    zkg = resolve_binary("zkg")
    version = run_command([zeek, "--version"], timeout=5) if zeek else {"ok": False, "stderr": "zeek not found"}
    running_pids = running_zeek_pids(zeekctl)
    spool_directory = Path(zeekctl).resolve().parent.parent / "spool" if zeekctl else None
    state_database = spool_directory / "state.db" if spool_directory else None
    can_manage = bool(state_database and os.access(str(state_database), os.W_OK))
    if zeekctl and can_manage:
        ctl_status = run_command([zeekctl, "status"], timeout=8)
    elif zeekctl and running_pids:
        ctl_status = {
            "ok": True,
            "returncode": 0,
            "stdout": f"Zeek process running (PID {', '.join(str(pid) for pid in running_pids)})",
            "stderr": "",
        }
    elif zeekctl:
        ctl_status = {
            "ok": False,
            "returncode": 1,
            "stdout": "",
            "stderr": "Zeek is not running. ZeekControl management requires sudo.",
        }
    else:
        ctl_status = {"ok": False, "stderr": "zeekctl not found"}
    log_directory = Path(zeek_config.get("log_directory", "/opt/zeek/logs/current"))
    configured_logs = zeek_config.get("context_logs", [])
    logs = []
    for log_type in configured_logs:
        path = log_directory / f"{log_type}.log"
        logs.append({"log_type": log_type, "path": str(path), **log_file_status(path)})
    return {
        "enabled": bool(zeek_config.get("enabled", True)),
        "interface": zeek_config.get("interface", "ens37"),
        "json_logs": bool(zeek_config.get("json_logs", True)),
        "log_directory": str(log_directory),
        "archive_directory": zeek_config.get("archive_directory", "/opt/zeek/logs"),
        "binaries": {
            "zeek": zeek,
            "zeekctl": zeekctl,
            "zkg": zkg,
        },
        "installed": bool(zeek and zeekctl),
        "version": version,
        "zeekctl_status": ctl_status,
        "running": bool(running_pids),
        "running_pids": running_pids,
        "management_requires_privilege": bool(zeekctl and not can_manage),
        "community_packages": zeek_config.get("community_packages", []),
        "package_install_enabled": bool(zeek_config.get("package_install_enabled", False)),
        "logs": logs,
    }

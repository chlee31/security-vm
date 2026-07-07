#!/usr/bin/env bash
set -euo pipefail

EXTERNAL_INTERFACE="${1:-ens33}"
INTERNAL_INTERFACE="${2:-ens37}"
OUTPUT_DIR="${3:-/var/log/pcap}"
APP_USER="${SECURITY_VM_USER:-${SUDO_USER:-${USER}}}"

sudo mkdir -p "$OUTPUT_DIR"
if command -v setfacl >/dev/null 2>&1; then
  sudo setfacl -m "u:${APP_USER}:rx,m:rx" "$OUTPUT_DIR"
  sudo setfacl -d -m "u:${APP_USER}:r,m:r" "$OUTPUT_DIR"
fi

fix_capture_permissions() {
  if ! command -v setfacl >/dev/null 2>&1; then
    return
  fi

  sudo bash -c '
    set -euo pipefail
    output_dir="$1"
    app_user="$2"
    while true; do
      shopt -s nullglob
      for file in "$output_dir"/*.pcapng; do
        setfacl -m "u:${app_user}:r,m:r" "$file" 2>/dev/null || true
      done
      sleep 2
    done
  ' _ "$OUTPUT_DIR" "$APP_USER" &
  ACL_PID=$!
}

cleanup() {
  if [[ -n "${ACL_PID:-}" ]]; then
    sudo kill "$ACL_PID" 2>/dev/null || true
  fi
}

trap cleanup EXIT INT TERM
fix_capture_permissions

start_capture() {
  local label="$1"
  local interface="$2"

  echo "[+] Starting $label capture on $interface"
  sudo dumpcap -i "$interface" \
    -b duration:600 \
    -b filesize:100000 \
    -b files:288 \
    -w "$OUTPUT_DIR/${label}-${interface}.pcapng" &
}

start_capture external "$EXTERNAL_INTERFACE"
start_capture internal "$INTERNAL_INTERFACE"

echo "[+] Writing rolling PCAPs to $OUTPUT_DIR"
echo "[+] Press Ctrl+C to stop both captures"
wait

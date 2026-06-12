#!/usr/bin/env bash
set -euo pipefail

EXTERNAL_INTERFACE="${1:-ens33}"
INTERNAL_INTERFACE="${2:-ens37}"
OUTPUT_DIR="${3:-/var/log/pcap}"

sudo mkdir -p "$OUTPUT_DIR"

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

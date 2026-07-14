#!/usr/bin/env bash

set -euo pipefail

SURICATA_CONFIG="${SURICATA_CONFIG:-/etc/suricata/suricata.yaml}"
ZEEK_LOCAL="${ZEEK_LOCAL:-/opt/zeek/share/zeek/site/local.zeek}"
ZEEKCTL="${ZEEKCTL:-/opt/zeek/bin/zeekctl}"
COMMUNITY_ID_SEED="${COMMUNITY_ID_SEED:-0}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this script with sudo: sudo ./scripts/enable_community_id.sh" >&2
  exit 1
fi

for path in "${SURICATA_CONFIG}" "${ZEEK_LOCAL}" "${ZEEKCTL}"; do
  if [[ ! -e "${path}" ]]; then
    echo "Required file not found: ${path}" >&2
    exit 1
  fi
done

timestamp="$(date +%Y%m%d%H%M%S)"
cp -a "${SURICATA_CONFIG}" "${SURICATA_CONFIG}.community-id.${timestamp}.bak"
cp -a "${ZEEK_LOCAL}" "${ZEEK_LOCAL}.community-id.${timestamp}.bak"

python3 - "${SURICATA_CONFIG}" "${COMMUNITY_ID_SEED}" <<'PY'
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
seed = int(sys.argv[2])
if not 0 <= seed <= 65535:
    raise SystemExit("Community ID seed must be between 0 and 65535")

text = path.read_text(encoding="utf-8")
updated, enabled_count = re.subn(
    r"(?m)^(\s*)community-id:\s*(?:false|no)\s*(?:#.*)?$",
    r"\1community-id: true",
    text,
)
updated, seed_count = re.subn(
    r"(?m)^(\s*)community-id-seed:\s*\d+\s*(?:#.*)?$",
    rf"\g<1>community-id-seed: {seed}",
    updated,
)
if enabled_count == 0 and not re.search(r"(?m)^\s*community-id:\s*(?:true|yes)\s*$", updated):
    raise SystemExit("Could not locate Suricata eve-log community-id setting")
if seed_count == 0 and not re.search(
    rf"(?m)^\s*community-id-seed:\s*{seed}\s*$", updated
):
    raise SystemExit("Could not locate Suricata community-id-seed setting")
path.write_text(updated, encoding="utf-8")
PY

ensure_zeek_line() {
  local line="$1"
  if ! grep -Fqx "${line}" "${ZEEK_LOCAL}"; then
    printf '\n%s\n' "${line}" >> "${ZEEK_LOCAL}"
  fi
}

ensure_zeek_line '@load policy/protocols/conn/community-id-logging'
ensure_zeek_line '@load policy/frameworks/notice/community-id'
ensure_zeek_line "redef CommunityID::seed = ${COMMUNITY_ID_SEED};"

echo "[+] Validating Suricata configuration"
suricata -T -c "${SURICATA_CONFIG}"

echo "[+] Validating Zeek configuration"
"${ZEEKCTL}" check

echo "[+] Restarting Suricata"
systemctl restart suricata

echo "[+] Deploying Zeek"
"${ZEEKCTL}" deploy

echo "[+] Community ID enabled with seed ${COMMUNITY_ID_SEED}"
systemctl --no-pager --full status suricata | sed -n '1,8p'
"${ZEEKCTL}" status

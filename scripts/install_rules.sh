#!/usr/bin/env bash
# =====================================================================
# install_rules.sh - Install and activate the SPR888 custom Suricata
# rules, then validate and reload Suricata. Run with sudo.
#
# Usage:  sudo ./scripts/install_rules.sh
# =====================================================================
set -euo pipefail

REPO_RULES="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/rules/local.rules"
SURICATA_YAML="/etc/suricata/suricata.yaml"
RULES_DEST="/etc/suricata/rules/local.rules"

echo "[+] Installing custom rules from: $REPO_RULES"

if [[ ! -f "$REPO_RULES" ]]; then
  echo "[!] Could not find rules/local.rules. Run this from the project root."
  exit 1
fi

# 1. Copy the rules into Suricata's rules directory
sudo mkdir -p /etc/suricata/rules
sudo cp "$REPO_RULES" "$RULES_DEST"
echo "[+] Copied rules to $RULES_DEST"

# 2. Make sure local.rules is referenced under rule-files: in suricata.yaml
if sudo grep -qE "^\s*-\s*local\.rules" "$SURICATA_YAML"; then
  echo "[+] local.rules already referenced in suricata.yaml"
else
  echo "[+] Adding local.rules to suricata.yaml rule-files list"
  sudo sed -i '/^rule-files:/a\  - local.rules' "$SURICATA_YAML"
fi

# 3. Validate configuration and rules
echo "[+] Validating Suricata configuration and rules..."
if sudo suricata -T -c "$SURICATA_YAML" -v; then
  echo "[+] Validation passed"
else
  echo "[!] Validation failed. Fix the errors above before reloading."
  exit 1
fi

# 4. Reload rules without dropping packets if possible, else restart
echo "[+] Reloading Suricata rules..."
if sudo suricatasc -c reload-rules 2>/dev/null; then
  echo "[+] Rules reloaded live via suricatasc"
else
  echo "[+] suricatasc unavailable, restarting suricata service"
  sudo systemctl restart suricata
fi

echo "[+] Done. Custom SPR888 rules are active."

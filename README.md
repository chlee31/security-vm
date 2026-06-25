# Security VM

Ubuntu security appliance prototype using Suricata, SQLite, rolling PCAP capture, tshark summaries, Ollama over Tailscale, and optional firewalld response.

The system is designed to start safely in `alert_only` mode. Python makes the final decision, Ollama only gives triage advice, and firewall blocking is disabled unless `auto_response` is explicitly configured.

## Current Status

This project currently runs with a few terminal commands. The next goal is a one-command launcher that starts Suricata checks, rolling PCAP capture, alert ingest, and the dashboard together.

For now, use this README as the group runbook.

## Project Layout

```text
security-vm/
  app/                         Python application code
  rules/local.rules            Sample Suricata local rules
  scripts/start_pcap_capture.sh Rolling PCAP capture helper
  sql/schema.sql               SQLite schema
  static/                      Dashboard frontend
  config.yaml.example          Example config
  requirements.txt             Python dependencies
```

## Fresh Setup

From a fresh clone or copied folder:

```bash
cd ~/Documents/security-vm
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python -m app.bootstrap
```

The bootstrap checks tools, creates `config.yaml`, initializes `security_vm.db`, and tests the Ollama endpoint if configured.

If `config.yaml` is missing, the app falls back to defaults. For group work, commit or share a safe example config, not private machine-specific values.

## Network Interfaces

Check interface names:

```bash
ip -br link
```

On the current VM, the working interfaces are:

```text
ens33  external network
ens37  internal network
```

If Suricata logs mention `eth0`, update `/etc/suricata/suricata.yaml`.

Find the old interface references:

```bash
sudo grep -n "interface: eth0" /etc/suricata/suricata.yaml
```

For the system service, the important section is usually `af-packet:`:

```yaml
af-packet:
  - interface: ens33
  - interface: ens37
```

If using pcap/libpcap capture mode, the `pcap:` section can also include both:

```yaml
pcap:
  - interface: ens33
  - interface: ens37
  - interface: default
```

## Suricata Rules

Copy the sample local rules:

```bash
sudo cp rules/local.rules /etc/suricata/rules/local.rules
```

Make sure `/etc/suricata/suricata.yaml` includes:

```yaml
rule-files:
  - local.rules
```

Test the Suricata config:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml
```

Restart Suricata:

```bash
sudo systemctl restart suricata
sudo systemctl status suricata
```

Watch logs:

```bash
sudo journalctl -u suricata -f
```

Watch EVE JSON output:

```bash
sudo tail -f /var/log/suricata/eve.json
```

## Run Everything Manually

Use separate terminals for now.

Terminal 1: Suricata

```bash
sudo systemctl restart suricata
sudo journalctl -u suricata -f
```

Terminal 2: alert ingest

```bash
cd ~/Documents/security-vm
source venv/bin/activate
sudo ./venv/bin/python -m app.main ingest --config config.yaml
```

Use `sudo ./venv/bin/python`, not `sudo python`, so the command keeps the virtualenv packages.

Ingest asks Ollama for an opinion on every Suricata alert. If Ollama is down or unreachable, the alert is still stored and the dashboard will show an Ollama unavailable report.

Terminal 3: dashboard

```bash
cd ~/Documents/security-vm
source venv/bin/activate
python -m app.main dashboard --config config.yaml --host 0.0.0.0 --port 8000
```

Open:

```text
http://127.0.0.1:8000/
```

Or from another machine:

```text
http://<security-vm-ip>:8000/
```

Terminal 4: rolling PCAP capture

```bash
cd ~/Documents/security-vm
chmod +x scripts/start_pcap_capture.sh
./scripts/start_pcap_capture.sh ens33 ens37 /var/log/pcap
```

This records both sides separately:

```text
/var/log/pcap/external-ens33...
/var/log/pcap/internal-ens37...
```

## Quick Test

Generate simple traffic:

```bash
ping 8.8.8.8
```

Then check:

```bash
sudo tail -f /var/log/suricata/eve.json
```

If ingest is running, alerts should be stored in SQLite and appear on the dashboard.
The dashboard has separate sections for raw Suricata alerts and Ollama opinions.

## Common Issues

### Suricata Keeps Restarting

Check logs:

```bash
sudo journalctl -u suricata -n 80 --no-pager
```

If you see:

```text
af-packet: eth0: failed to find interface: No such device
```

Suricata is configured for the wrong interface. Replace `eth0` with the real names from:

```bash
ip -br link
```

### Permission Denied Reading eve.json

If ingest fails with:

```text
PermissionError: [Errno 13] Permission denied: '/var/log/suricata/eve.json'
```

Run ingest with the virtualenv Python under sudo:

```bash
sudo ./venv/bin/python -m app.main ingest --config config.yaml
```

### Missing Python Packages With sudo

Do not run:

```bash
sudo python -m app.main ingest --config config.yaml
```

That may use system Python and miss packages from `venv`.

Use:

```bash
sudo ./venv/bin/python -m app.main ingest --config config.yaml
```

### Dashboard API Says no such table: alerts

Initialize the database:

```bash
cd ~/Documents/security-vm
sudo ./venv/bin/python -c "from app.database import init_db; conn = init_db('security_vm.db'); conn.close()"
```

Then restart the dashboard.

### Dashboard Shows No Alerts

Check:

```bash
sudo systemctl status suricata
sudo tail -f /var/log/suricata/eve.json
sudo ./venv/bin/python -m app.main ingest --config config.yaml
```

Also confirm the dashboard and ingest are using the same database path in `config.yaml`.

## Ollama Over Tailscale

The expected Ollama API shape is:

```text
http://<tailscale-ip>:11434
```

Test from the Security VM:

```bash
curl http://<tailscale-ip>:11434/api/tags
```

The ingest process calls Ollama on every normalized Suricata alert using:

```text
POST /api/generate
```

Ollama returns an opinion with:

```text
classification, confidence, risk_adjustment, reason, recommended_action
```

These opinions are saved in SQLite and shown on the dashboard separately from the Suricata alert stream.

The default model used during development was:

```text
llama3.2:latest
```

## Safety Notes

- Default mode is `alert_only`.
- Ollama does not execute firewall actions.
- Python is the final controller.
- Do not send raw PCAP binaries to Ollama.
- Store alerts and evidence before acting.
- Check allowlist and safelist before blocking.
- Temporary firewall blocks should only happen in explicit `auto_response` mode.

## Planned One-Command Launcher

The desired final flow is one command that:

- validates Suricata config and interface names
- starts or verifies Suricata
- initializes SQLite
- starts rolling PCAP capture for `ens33` and `ens37`
- starts alert ingest
- starts the dashboard
- prints useful log locations and dashboard URL

Until that launcher exists, use the manual run flow above.

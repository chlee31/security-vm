# Security VM

Security VM is an Ubuntu-based security dashboard prototype. It watches Suricata alerts, Zeek behavioral logs, and rolling PCAP evidence, stores them in SQLite, asks a configured AI model for a second opinion, and shows analyst review information in a browser dashboard.

The system starts in safe `alert_only` mode. The AI model can recommend actions, but Python makes the final decision. Firewall blocking is disabled unless `prevention` mode is explicitly enabled.

## System Workflow

See the [complete Security VM workflow](docs/SECURITY_VM_WORKFLOW.md) for a visual map of bootstrap, network sensors, correlation, threat intelligence, AI triage, scoring, firewall response, and analyst review.

## Screenshots

Main dashboard with Suricata detections, asset inventory, enrichment status, and visible risk scores:

![Security VM dashboard overview](docs/images/dashboard-overview.png)

Detection workbooks break down each alert type with IP share, AI opinions, timeline, evidence, and recent alerts:

![DNS tunneling detection workbook](docs/images/dns-tunneling-workbook.png)

![Port scan detection workbook](docs/images/port-scan-workbook.png)

![Unknown detection workbook](docs/images/unknown-detection-workbook.png)

Admin controls let users update AI model settings, registered machines, asset status, and local tool checks:

![Admin controls](docs/images/admin-controls.png)

Home AI/GPU usage during triage with an NVIDIA GeForce RTX 4070 Ti SUPER:

![GPU usage while running the AI model at home](docs/images/gpu-ai-home.png)

## What It Shows

- Unified latest alerts with Suricata and Zeek findings, timestamps, flows, and sensor labels
- Zeek notice, weird, and protocol context logs
- Detection types and investigation drilldowns
- Dedicated detection workbook tabs with IP share, AI opinion, timeline, and evidence
- Dedicated outcome workbook tabs for Safe, Human Review, and Dangerous decisions
- Dedicated asset inventory workbook for registered internal machines and their matched detections
- AI opinions for alerts
- AI model comparison by provider/model identity, classification, average adjustment, and average response time
- Decision evidence: alert data, correlation, score, AI reason, and final action
- Zeek sensor status, correlated findings, and incident evidence paths
- Human-review queue
- Temporary allowlist entries
- Manual internal asset inventory for lab machines on `ens37`
- Admin controls for registered machine IPs, AI service URL/model settings, and installed tool checks
- Runtime logs and enrichment status

## Feature Status

These features are available in the dashboard today. Some still have planned refinements listed in their notes.

Asset inventory:

- Add internal machines manually by IP address, name, device type, function, and notes.
- Device type applies a default asset score.
- Current lab target is the internal `ens37` network.
- Open `/asset-inventory` from the dashboard to review registered machines, score distribution, device types, and matching detections.
- Asset context is shown in detection detail and decision evidence.
- When alert traffic matches a registered source or destination IP, the asset score is added to Python's initial risk score.
- The matched asset details and applied score are sent to the AI model as analyst-defined context.

Human review tuning:

- Analysts can confirm or override human-review alerts.
- Reviews can be labeled as true positive, false positive, authorized test, or unknown.
- Labels are stored in SQLite for later tuning work.
- The model does not automatically learn from those labels yet.

Threat enrichment:

- Local IP classification works now.
- Open `/admin#threat-intel` to enable and configure threat-intelligence providers.
- Supported cached feeds are ThreatFox, URLhaus, SSLBL, Spamhaus DROP, OpenPhish Community, IPsum, and Feodo Tracker.
- OTX remains a live API provider with connection testing and a manual top-10 public-IP lookup from Admin.
- VirusTotal is a post-AI verification provider. Python queries public source/destination IPs only after the AI model returns `Dangerous`, then caches and stores the result.
- Active bulk feeds are refreshed on their configured schedule and normalized into SQLite. A failed refresh keeps the last successful cache.
- API keys are saved only in the local `config.yaml`; never commit that file or paste keys into issues or screenshots.
- Python sends matching cached intelligence to the AI model. The model does not browse or call provider APIs itself.
- Provider cards show indicator counts plus how many detection prompts actually used each feed and when it was last used.
- Investigation and IP-address pages show each provider as matched, no match, or `Not active`.

PCAP evidence:

- Rolling PCAP capture remains a backend evidence source and is not displayed as a dashboard panel.
- The AI model receives related PCAP file metadata as evidence context, including capture label, file size, and modified time.
- Python selects a small number of related PCAP files, converts them into compact `tshark` CSV summaries, and includes those text summaries in the AI prompt.
- Raw PCAP bytes are not sent to the AI model.

Zeek evidence:

- Zeek is configured as a second network sensor. Bootstrap asks which detected interface it should monitor; the project default is `ens37`.
- Zeek `notice.log` is treated as an alert-like finding; `weird.log` is retained as investigation context.
- Every Suricata alert and every Zeek `notice.log` finding enters the same AI and Python decision pipeline.
- Correlated Suricata and Zeek findings are stored under one detection as separate sensor findings; `weird.log` remains supporting context unless another detection corroborates it.
- Sensor correlation uses Community ID first, then bidirectional IP/port/protocol matching with timestamp tolerance.
- Zeek `conn`, `dns`, `http`, `ssl`, `files`, `ssh`, and `x509` logs are treated as supporting context.
- The dashboard combines Zeek and Suricata findings under the same latest-alert and decision-evidence rows.
- Investigation pages can create a server-generated evidence folder with filtered Zeek context and a manifest.
- Zeek community detections are managed through `zkg` packages, not Suricata-style rule files.
- The default reviewed community package list contains `ncsa/bro-simple-scan` and `jbaggs/anomalous-dns`. Bootstrap asks before installing either package with `zkg`.

Multi-sensor correlation:

Enable Community ID in the EVE output section of `/etc/suricata/suricata.yaml`:

```yaml
community-id: true
community-id-seed: 0
```

Load matching Community ID policies from `/opt/zeek/share/zeek/site/local.zeek`:

```zeek
@load policy/protocols/conn/community-id-logging
@load policy/frameworks/notice/community-id
```

Then validate and restart both sensors:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml
sudo systemctl restart suricata
sudo /opt/zeek/bin/zeekctl check
sudo /opt/zeek/bin/zeekctl deploy
```

Both sensors must use the same Community ID seed. When Community ID is unavailable, Security VM falls back to flow fields and overlapping event timestamps.

Dashboard reset:

- The Runtime panel has a reset control for clearing dashboard history during demos.
- Reset clears alerts, detections, AI reports, responses, review queue, evidence, runtime logs, and cached threat-intel rows.
- Reset keeps the asset inventory, allowlist entries, and local configuration.

Admin controls:

- Open `/admin` from the dashboard header.
- Use the Threat Intelligence tab to enable providers, set API keys and refresh intervals, refresh active bulk feeds, and run OTX connection/manual lookup checks. VirusTotal is invoked by the detection pipeline, not the feed-refresh button.
- Switch between `alert_only`, `detection`, and `prevention` mode.
- View firewalld setup commands, running status, applied rich rules, dangerous detections awaiting enforcement, active firewall blocks, firewall history, and unblock or mark an IP safe.
- Change the AI service URL, model name, and timeout without editing `config.yaml` manually.
- Set a provider label such as `ollama`, `nvidia`, or `deepseek` so reports can be compared by engine.
- Suggested model names include `llama3.1:8b`, `llama3.2:latest`, and DeepSeek options for future testing.
- View and edit registered internal machine IP addresses stored in SQLite.
- Mark inventory records inactive to preserve tracking history, or permanently delete mistaken entries from admin controls.
- Configure Gmail alerts for Dangerous decisions, send a test email, and review sent/failed/skipped notification history.
- View required system tools and Python packages detected on the Security VM, including version numbers when available.
- Copy install or update commands from the admin page. Run system package commands in the terminal because they usually require `sudo`.
- If `dumpcap` is installed but marked permission-limited, add the user to the `wireshark` group or run packet capture with sudo.

Gmail alerts:

- Use a dedicated Gmail sender account for the application.
- Enable 2-Step Verification on that Gmail account and create a Gmail app password.
- Do not use the normal Gmail login password. Google rejects normal account passwords for this SMTP workflow.
- Gmail app passwords are usually shown as 16 characters, often grouped with spaces. The dashboard removes spaces before saving, but the saved value should still be 16 characters.
- In `/admin`, enter the sender Gmail address, the 16-character app password, recipient email list, cooldown minutes, and optional dashboard base URL.
- Use "Save and Send Test Email" before relying on Dangerous alert notifications.
- The dashboard does not display the saved app password after it is stored.

## Prerequisites

Recommended OS:

```text
Ubuntu 22.04 or newer
```

The tested Zeek bootstrap path is not recommended on Ubuntu releases older than 22.04. Bootstrap detects `/etc/os-release`, displays the result, and asks before continuing on an unsupported host.

Required system tools:

```text
python3
python3-venv
python3-pip
suricata
suricata-update
zeek
zeekctl
zkg
sqlite3
wireshark-common
tshark
dumpcap
curl
```

Optional tools:

```text
tailscale      needed if the AI service is reached over Tailscale
firewalld      needed only for prevention-mode firewall blocking
git            needed for cloning and branch workflow
```

These are not required for the basic dashboard, ingest, SQLite storage, and Suricata alert viewing flow. Install them only when using the related optional workflow.

Install common Ubuntu dependencies:

```bash
sudo apt update
sudo apt install python3 python3-venv python3-pip sqlite3 curl suricata suricata-update wireshark-common tshark
```

Bootstrap installs Zeek from the official Zeek OBS repository when Zeek is missing on a supported Ubuntu host. To run that guided setup:

```bash
python -m app.bootstrap
```

If automatic installation fails, follow the official Zeek binary package instructions, then rerun:

```bash
python -m app.bootstrap
python -m app.main zeek-status --config config.yaml
```

Zeek community detections are installed with `zkg`. Add reviewed packages to `config.yaml`:

```yaml
zeek:
  community_packages:
    - ncsa/bro-simple-scan
    - jbaggs/anomalous-dns
  package_install_enabled: true
```

Then rerun bootstrap and approve each package install. Do not add unreviewed community packages just because they exist online.

## Installed By Python

These packages are installed by:

```bash
pip install -r requirements.txt
```

Current Python packages:

```text
fastapi     dashboard API framework
uvicorn     web server for the dashboard
PyYAML      config.yaml parsing
requests    AI model and HTTP API calls
```

FastAPI also installs supporting packages such as `pydantic` and `starlette`.

Everything else imported by the app, such as `sqlite3`, `json`, `ipaddress`, `argparse`, `pathlib`, `datetime`, and `subprocess`, comes from the Python standard library.

Python version:

```text
Python 3.8 or newer
```

Check:

```bash
python3 --version
```

## Quick Start

Clone and enter the project:

```bash
git clone https://github.com/chlee31/security-vm.git
cd security-vm
```

Create the Python environment:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Run bootstrap:

```bash
python -m app.bootstrap
```

Bootstrap preserves an existing `config.yaml` unless you approve changes, initializes or migrates `security_vm.db`, checks the Ubuntu version and required tools, and tests the AI model endpoint. It also offers official Zeek installation, interface selection, `node.cfg`, JSON logging, and optional reviewed `zkg` community-package installation.

Bootstrap can also guide router setup:

- Detects available network interfaces with `ip -j addr`.
- Shows the current default external route.
- Asks which interface is external/internet and which is internal/lab.
- Suggests `192.168.11.1/24` as the internal router address, or lets you enter another CIDR.
- Generates a permanent netplan file for the two-interface router layout.
- Enables IPv4 forwarding with `/etc/sysctl.d/99-security-vm-router.conf`.
- Enables firewalld masquerading on the external zone.
- Prints the manual IPv4 settings to use on lab devices, including IP, gateway, prefix, and DNS.

Router setup is optional and asks before applying system changes.

## Run The System

Start the full local stack with one command:

```bash
cd ~/Documents/security-vm
source venv/bin/activate
sudo ./venv/bin/python -m app.main run-all --config config.yaml --host 0.0.0.0 --port 8000
```

This starts:

```text
Suricata service restart/check
rolling PCAP capture
Suricata EVE ingest
Zeek ingest
scheduled threat-intelligence feed refresh
dashboard API and web UI
```

Normal logs are kept quiet. If a process fails or prints an error, the launcher prints the error line and a short recent log tail in the terminal.

The dashboard loads once and updates only when you press **Refresh**. This prevents new ingest data from moving the page while an analyst is reading evidence.

By default, `run-all` uses:

```text
external interface: ens33
internal interface: ens37
pcap directory: /var/log/pcap
Zeek interface: selected during bootstrap (default ens37)
Zeek log directory: /opt/zeek/logs/current
dashboard: http://0.0.0.0:8000/
```

Override those when needed:

```bash
sudo ./venv/bin/python -m app.main run-all \
  --config config.yaml \
  --host 0.0.0.0 \
  --port 8000 \
  --external-interface ens33 \
  --internal-interface ens37 \
  --pcap-dir /var/log/pcap
```

Command-line interface overrides only affect that one run. To make the launcher use different capture interfaces every time, edit `config.yaml`:

```yaml
pcap:
  rolling_dir: /var/log/pcap
  external_interface: ens33
  internal_interface: ens37
  max_ai_files: 2
  summary_packet_limit: 20
  summary_timeout_seconds: 20

zeek:
  enabled: true
  interface: ens37
  log_directory: /opt/zeek/logs/current
  json_logs: true
  community_packages: []
```

Zeek-only checks:

```bash
python -m app.main zeek-status --config config.yaml
python -m app.main zeek-ingest --config config.yaml
```

The PCAP AI settings mean:

```text
max_ai_files              maximum related PCAP files summarized per detection
summary_packet_limit      maximum packets included in each tshark text summary
summary_timeout_seconds   timeout for each tshark summary command
```

Use the interface names shown by:

```bash
ip -br link
```

This project setting only controls which interfaces Security VM captures from. If you need to permanently change the Ubuntu machine's actual interface IP addresses, gateway, DNS, or router behavior, use the bootstrap router setup or edit netplan separately.

If Suricata is managed differently on your machine, skip the service restart:

```bash
sudo ./venv/bin/python -m app.main run-all --config config.yaml --skip-suricata-restart
```

Use `sudo ./venv/bin/python`, not `sudo python`, so sudo still uses the project virtual environment.

Open:

```text
http://127.0.0.1:8000/
```

From another machine, use:

```text
http://<security-vm-ip or Tailscale IP address>:8000/
```

Admin controls:

```text
http://<security-vm-ip>:8000/admin
```

Fallback manual commands for troubleshooting:

Terminal 1: start or watch Suricata

```bash
sudo systemctl restart suricata
sudo journalctl -u suricata -f
```

Terminal 2: start ingest

```bash
cd ~/Documents/security-vm
source venv/bin/activate
sudo ./venv/bin/python -m app.main ingest --config config.yaml
```

Terminal 3: start dashboard

```bash
cd ~/Documents/security-vm
source venv/bin/activate
python -m app.main dashboard --config config.yaml --host 0.0.0.0 --port 8000
```

Terminal 4: start rolling PCAP capture

```bash
cd ~/Documents/security-vm
chmod +x scripts/start_pcap_capture.sh
./scripts/start_pcap_capture.sh ens33 ens37 /var/log/pcap
```

This records:

```text
ens33 -> external capture
ens37 -> internal capture
```

## Test It

Generate simple traffic:

```bash
ping 8.8.8.8
```

Watch Suricata output:

```bash
sudo tail -f /var/log/suricata/eve.json
```

If ingest is running, alerts should appear in SQLite and on the dashboard.

## Suricata Setup

Check network interfaces:

```bash
ip -br link
```

Current lab interface convention:

```text
ens33  external network
ens37  internal network
```

Check active Suricata rules:

```bash
sudo grep -n -A 20 -B 5 "rule-files:" /etc/suricata/suricata.yaml
```

Expected default-rule setup:

```yaml
default-rule-path: /var/lib/suricata/rules

rule-files:
  - suricata.rules
```

Update default rules:

```bash
sudo suricata-update
```

Test and restart Suricata:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml
sudo systemctl restart suricata
sudo systemctl status suricata
```

If Suricata complains about `eth0`, edit `/etc/suricata/suricata.yaml` and use the real interface names:

```yaml
af-packet:
  - interface: ens33
  - interface: ens37
```

## AI Model Setup

The AI model service should be reachable from the Security VM over Tailscale:

```text
http://<tailscale-ip>:11434
```

Test it:

```bash
curl http://<tailscale-ip>:11434/api/tags
```

If the dashboard shows an API error after configuring Tailscale, confirm the AI model service is listening on an address Tailscale can reach. A common issue is that the model server is only bound to `127.0.0.1`, which means it works on the AI machine itself but not from the Security VM over Tailscale.

For Ollama, configure it to listen on the Tailscale-reachable interface, then restart Ollama:

```bash
sudo systemctl edit ollama
```

Add:

```ini
[Service]
Environment="OLLAMA_HOST=0.0.0.0:11434"
```

Then run:

```bash
sudo systemctl daemon-reload
sudo systemctl restart ollama
curl http://<tailscale-ip>:11434/api/tags
```

On a Windows Ollama host, run PowerShell or CMD as Administrator:

```powershell
setx OLLAMA_HOST "0.0.0.0:11434" /M
taskkill /IM ollama.exe /F
netsh advfirewall firewall add rule name="Allow Ollama 11434" dir=in action=allow protocol=TCP localport=11434
```

Then reopen Ollama.

If the AI host is using Tailscale Serve, expose the local Ollama port:

```powershell
tailscale serve --bg --tcp=11434 tcp://localhost:11434
tailscale serve status
```

From the Ubuntu Security VM, test the Windows host over Tailscale:

```bash
curl http://<windows-tailscale-ip>:11434/api/tags
```

Example:

```bash
curl http://100.99.223.100:11434/api/tags
```

Use the same reachable URL in the Admin AI profile, for example `http://<tailscale-ip>:11434`.

The default model used during development:

```text
llama3.2:latest
```

Ingest asks the configured AI model for an opinion on every normalized Suricata alert. If the model service is unavailable, the alert is still stored and the dashboard records the failure.

Each AI report stores:

```text
ai_profile_uid   stable UID for the selected Admin AI profile
model_provider   example: ollama, nvidia, deepseek
model_name       example: llama3.1:8b
model_identity   example: ollama:llama3.1:8b
model_run_id     unique ID for that specific AI opinion
prompt_version   prompt template version used for the request
prompt_sha256    hash of the full prompt sent to the AI model
prompt_chars     prompt size in characters
pcap_summary_sha256 / pcap_summary_chars / pcap_summary_included
                 audit fields showing whether packet summaries were included
elapsed_ms       model response time
```

Use the Admin page to create AI profiles such as `Home GPU`, `Local Llama 3.1`, `NVIDIA NIM`, or `DeepSeek`. Selecting a profile writes it to `config.yaml`, and every new AI report is stamped with that profile UID plus a unique run ID so different engines can be compared later.

## Useful Commands

Initialize or repair the SQLite schema:

```bash
./venv/bin/python -c "from app.database import init_db; conn = init_db('security_vm.db'); conn.close()"
```

Backfill missing AI reports for the currently configured model identity:

```bash
python -m app.main ai-backfill --config config.yaml --limit 500
```

If you switch from one model to another, run `ai-backfill` again. The command skips only detections that already have a report from the current `provider:model` identity, so it can create side-by-side opinions for comparison.

Check Python syntax:

```bash
./venv/bin/python -m compileall app
```

Check PCAP files:

```bash
sudo ls -lh /var/log/pcap
```

## Common Problems

### Suricata keeps restarting

Check logs:

```bash
sudo journalctl -u suricata -n 80 --no-pager
```

If you see `eth0: No such device`, Suricata is listening on the wrong interface. Use:

```bash
ip -br link
```

Then update `/etc/suricata/suricata.yaml`.

### Ingest cannot read eve.json

Run ingest with the virtualenv Python under sudo:

```bash
sudo ./venv/bin/python -m app.main ingest --config config.yaml
```

### Dashboard shows no alerts

Check these:

```bash
sudo systemctl status suricata
sudo tail -f /var/log/suricata/eve.json
sudo ./venv/bin/python -m app.main ingest --config config.yaml
```

Also confirm dashboard and ingest use the same `database.path` in `config.yaml`.

### Dashboard API says no such table

Initialize the database:

```bash
./venv/bin/python -c "from app.database import init_db; conn = init_db('security_vm.db'); conn.close()"
```

### Dashboard API error after Tailscale setup

If the dashboard can load but AI-related API calls fail, test the model endpoint from the Security VM:

```bash
curl http://<tailscale-ip>:11434/api/tags
```

If this fails, the AI service is usually not listening on the Tailscale-reachable address, Windows Firewall is blocking the port, or Tailscale Serve is not exposing the local service. Update the model service binding, restart it, confirm the firewall rule, check `tailscale serve status`, and save the reachable Tailscale URL in `/admin`.

## Project Layout

```text
security-vm/
  app/                         Python backend
  rules/local.rules            Optional local Suricata rules
  scripts/start_pcap_capture.sh Rolling PCAP capture helper
  sql/schema.sql               SQLite schema
  static/                      Dashboard frontend
  config.yaml.example          Example config
  requirements.txt             Python dependencies
```

## Safety Notes

- Default mode is `alert_only`.
- Python makes final decisions.
- The AI model does not execute firewall actions.
- Raw PCAP files are not sent to the AI model.
- Alerts and evidence are stored before any action.
- Allowlist and safelist checks happen before blocking.
- Temporary firewall blocks only happen in explicit `prevention` mode.
- `alert_only` stores alerts and shows dangerous decisions without enforcement.
- `detection` runs the same scoring path as prevention, but queues dangerous would-block decisions for analyst approval instead of calling firewalld automatically.
- `prevention` can call firewalld for high-confidence dangerous decisions.
- Gmail notifications are only intended for Dangerous decisions and use a cooldown to avoid repeated emails for the same target.

## Current Notes

Anything not listed in the main run flow should be treated as an optional or planned workflow until it is documented here with setup and test steps.

## README Rule

When adding or pulling new features, update this README if the change affects:

- setup steps
- required packages
- config values
- run commands
- dashboard behavior
- troubleshooting
- safety behavior

This keeps the repo usable for teammates who clone it fresh.

# Security VM

Security VM is a research prototype that combines Suricata alerts, Zeek network metadata, cached threat intelligence, and locally hosted AI explanations into investigation cases.

For questions or project inquiries, contact **chlee31@myseneca.ca**.

## Install

### 1. Prerequisites

Use **Ubuntu 22.04 or newer** with:

- Python 3.10 or newer
- Git and curl
- Suricata with EVE JSON enabled
- Zeek, ZeekControl, and `zkg`
- A reachable Ollama-compatible AI service

Suricata and Zeek are both required. Follow the [official Suricata Quickstart Guide](https://docs.suricata.io/en/latest/quickstart.html) to install Suricata, configure its monitoring interface, install ET Open rules, and enable `/var/log/suricata/eve.json`.

### 2. Download Security VM

```bash
git clone https://github.com/chlee31/security-vm.git
cd security-vm
git switch dev
```

### 3. Create the Python Environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp config.yaml.example config.yaml
```

Python installs FastAPI, Uvicorn, PyYAML, and Requests. SQLite support is included with Python; the application creates its database automatically.

### 4. Run Setup

```bash
python -m app.bootstrap
```

Bootstrap checks the OS and required tools, asks for the AI service address and model, configures Zeek, initializes SQLite, and can enable matching Community IDs.

If Community ID was not enabled during bootstrap, run:

```bash
sudo ./scripts/enable_community_id.sh
```

## Start The Prototype

Activate the environment and start every required worker:

```bash
cd security-vm
source venv/bin/activate
python -m app.main run-all --config config.yaml
```

Open:

```text
http://127.0.0.1:8000
```

Stop the dashboard and all workers with `Ctrl+C`.

### Remote Dashboard Access

Bind only to a trusted management address:

```bash
export SECURITY_VM_ADMIN_USER=admin
read -rsp "Security VM admin password: " SECURITY_VM_ADMIN_PASSWORD
export SECURITY_VM_ADMIN_PASSWORD
echo
python -m app.main run-all --config config.yaml --host 192.168.57.134 --port 8000
```

Then open `http://192.168.57.134:8000`. Replace the address with the Security VM's management IP. Avoid `0.0.0.0` unless the lab network is isolated because it exposes the dashboard on every interface.

## Confirm It Is Working

Check both required sensors:

```bash
sudo systemctl status suricata --no-pager
python -m app.main zeek-status --config config.yaml
sudo /opt/zeek/bin/zeekctl status
```

Confirm that records are arriving:

```bash
sudo tail -f /var/log/suricata/eve.json
sudo tail -f /opt/zeek/logs/current/conn.log
```

Normal `run-all` output is quiet. Worker errors and unexpected exits appear in the terminal.

## Common Configuration

Edit `config.yaml` before starting the prototype. Restart `run-all` after changing these values.

| Setting | Purpose | Example |
| --- | --- | --- |
| `database.path` | SQLite database file | `security_vm.db` |
| `suricata.eve_json_path` | Suricata alert stream | `/var/log/suricata/eve.json` |
| `zeek.interface` | Interface monitored by Zeek | `ens37` |
| `zeek.log_directory` | Current Zeek logs | `/opt/zeek/logs/current` |
| `ai_model.host` | Ollama-compatible API address | `http://100.99.223.100:11434` |
| `ai_model.model` | Exact model name returned by `/api/tags` | `llama3.1:8b` |
| `ai_model.timeout_seconds` | Maximum request wait | `90` |
| `ai_model.num_ctx` | Input and output context window | `8192` |
| `ai_model.num_predict` | Maximum generated output | `1024` |
| `ai_model.temperature` | Response variation | `0.0` |
| `ai_model.seed` | Repeatability control | `42` |

Do not commit `config.yaml`, databases, logs, passwords, or API keys.

## Dashboard

### Overview

![Security VM dashboard](docs/images/dashboard-overview.png?raw=1)

The dashboard shows sensor activity, Zeek health, and combined Suricata and Zeek cases. Select **Refresh** to load new data without interrupting your current reading position.

### Case Investigation

![Security VM case investigation](docs/images/case-investigation.png?raw=1)

Each case has a stable UID and contains timestamps, endpoints, correlated sensor findings, threat-intelligence results, AI interpretation, and analyst review controls. Original Suricata and Zeek records remain available for audit.

## How It Works

```text
Mirrored traffic
      |
      v
Suricata alerts + Zeek metadata
      |
      v
Normalized records in SQLite
      |
      v
Python correlation and case creation
      |
      v
Cached threat-intelligence matching
      |
      v
Bounded AI prompt and JSON response
      |
      v
Case investigation and analyst review
```

Suricata and Zeek ingestion run separately from AI processing. Sensor evidence is stored immediately, while the AI worker processes persisted cases one at a time. A slow AI response therefore does not stop sensor ingestion.

Community ID is the preferred cross-sensor flow identifier. Both sensors use seed `0`. When it is unavailable, Python can use Zeek UID relationships and bounded flow/time matching.

## AI Data Handling

Security VM does not upload log files, databases, API keys, or packet captures to the model. Python selects relevant local records, converts them into bounded structured JSON text, and includes that text in one prompt sent to the Ollama-compatible `/api/generate` endpoint.

The configured `num_ctx` is a token window, not a file-size limit. With `num_ctx: 8192` and `num_predict: 1024`, Python reserves up to 1,024 tokens for output and budgets the remaining context for instructions and evidence.

Each request stores an audit record containing the exact prompt, normalized evidence, omissions, request settings, hashes, measured token use, and returned JSON. API keys are excluded.

The model returns one qualitative classification:

- `Safe`
- `Analyst Review Required`
- `Dangerous`

Low-confidence, invalid, missing, or materially disputed conclusions are routed to analyst review. AI output is advisory; Python retains control of storage, validation, and action mapping.

## Threat Intelligence

Threat-intelligence providers are configured under **Admin > Threat Intelligence**. Cached sources include ThreatFox, URLhaus, SSLBL, Spamhaus DROP, OpenPhish Community, IPsum, Feodo Tracker, and OTX.

Python extracts bounded observables from the case and matches them locally against enabled provider caches before AI review. VirusTotal is separate post-AI verification for eligible global IPs associated with a `Dangerous` result. Private, loopback, link-local, multicast, reserved, and `100.64.0.0/10` addresses are not queried.

## Remote AI Over Tailscale

On a Windows AI host, run these commands in Administrator PowerShell:

```powershell
setx OLLAMA_HOST "0.0.0.0:11434" /M
taskkill /IM ollama.exe /F
netsh advfirewall firewall add rule name="Allow Ollama 11434" dir=in action=allow protocol=TCP localport=11434
tailscale serve --bg --tcp=11434 tcp://localhost:11434
tailscale serve status
```

Restart Ollama, then test from Security VM:

```bash
curl http://YOUR_TAILSCALE_IP:11434/api/tags
```

Use that address for `ai_model.host` in `config.yaml`.

## Network Placement

Security VM is a passive monitoring prototype. Connect its monitoring interface to a switch SPAN or mirror destination and configure both sensors to observe that interface. Bootstrap does not configure routing, NAT, packet filtering, or client gateways.

## Test

```bash
source venv/bin/activate
python -m unittest discover -s tests -v
python -m compileall app
```

## Project Limits

- No endpoint process or user telemetry
- No decrypted payload inspection
- No autonomous firewall response
- No built-in authentication for the main dashboard
- No replacement for analyst judgment

## Documentation

- [Workflow](docs/SECURITY_VM_WORKFLOW.md)
- [Code walkthrough](docs/CODE_WALKTHROUGH.md)
- [Code and configuration guide](docs/CODE_AND_CONFIGURATION_GUIDE.md)
- [AI evidence audit](docs/ai-evidence-audit.md)

## Contact

Project inquiries: **chlee31@myseneca.ca**

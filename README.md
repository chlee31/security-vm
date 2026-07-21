# Security VM

Security VM is an AI-assisted network security monitoring and investigation research prototype. It combines Suricata findings and Zeek network metadata into centralized cases, adds registered-IP and threat-intelligence context, and asks locally configured AI models to explain the evidence and recommend investigation steps.

Python retains control of correlation, scoring, classifications, data handling, and safety boundaries. AI output is advisory and receives bounded structured evidence without API keys or raw packet captures.

## Current Scope

Security VM currently provides:

- passive network evidence collection from required Suricata and Zeek sensors;
- deterministic case construction and evidence-preserving SQLite storage;
- cached threat-intelligence enrichment and post-AI VirusTotal verification;
- explainable prioritization, AI-assisted summaries, and human review controls;
- sequential three-model comparison using one frozen evidence package.

The project is an **analysis platform**. It is not an endpoint agent, decrypted-payload inspection system, production firewall, autonomous response engine, or replacement for analyst judgment. The intended deployment uses copied traffic from a SPAN or mirror port. An optional routing wizard remains available only for isolated development labs.

## Workflow

```text
Mirrored or lab-routed network traffic
             |
             v
      Suricata + Zeek
             |
             v
 Original events stored in SQLite
             |
             v
 Deterministic correlation and case construction
             |
             v
 Registered IP + cached threat-intelligence enrichment
             |
             v
 Explainable Python score (0-80)
             |
             v
 Bounded AI explanation and adjustment (-10 to +10)
             |
             v
 Python-controlled outcome + optional VirusTotal verification
             |
             v
 Centralized investigation + analyst review
             |
             v
 Optional sequential three-model comparison
```

See [SECURITY_VM_WORKFLOW.md](docs/SECURITY_VM_WORKFLOW.md) for the detailed data flow.

## Core Features

- Required live Suricata and Zeek sensors
- Original Suricata EVE alerts and Zeek JSON records stored in SQLite
- Stable case, Suricata-event, and Zeek-event UIDs
- Community ID, Zeek UID, bidirectional flow, timestamp, and repeated-behavior correlation
- Conservative same-sensor grouping for scans, DNS tunneling, beaconing, brute force, and repeated identical findings
- Bounded Zeek context from `conn`, `dns`, `http`, `ssl`, `notice`, `weird`, `files`, `ssh`, and `x509` logs
- Zeek-derived IPs, DNS answers, domains, URLs, TLS/certificate fingerprints, JA3 values, file hashes, and SSH host keys matched against active cached threat-intelligence feeds with source-log and endpoint provenance
- Admin-managed IP addresses, assigned roles, and business-impact scores
- Cached threat-intelligence providers plus post-AI VirusTotal verification
- Five-category deterministic score with a complete SQLite audit trail
- Evidence-grounded AI explanation of who, what, when, where, why, how, and next steps
- Analyst confirmation, override, notes, and tuning labels
- Manual dashboard refresh so the page does not jump while an analyst is reading

## Interface

### Dashboard Overview

![Security VM dashboard overview](docs/images/dashboard-overview.png?raw=1)

The dashboard summarizes sensor findings, centralized cases, outcome queues, encrypted-traffic metadata, model activity, and Zeek health. Data changes only when the analyst selects **Refresh**.

### Case Investigation

![Centralized case investigation](docs/images/case-investigation.png?raw=1)

Each case has a stable UID and brings together timestamps, sensor findings, network endpoints, registered-IP context, threat intelligence, AI explanations, reassessment, and analyst feedback.

### Zeek Telemetry

![Zeek telemetry and ingestion health](docs/images/zeek-telemetry.png?raw=1)

The Zeek workspace shows sensor state, ingestion checkpoints, log volumes, and protocol metadata from connection, DNS, HTTP, TLS, file, notice, weird, SSH, and X.509 records.

### AI Model Comparison

![Three-model case summary comparison](docs/images/ai-comparison.png?raw=1)

Three configured models receive the same frozen evidence sequentially. Their complete responses and threat-intelligence inputs remain visible for direct analyst evaluation.

<details>
<summary><strong>Administration and threat-intelligence screenshots</strong></summary>

![Threat-intelligence provider status and controls](docs/images/threat-intelligence.png?raw=1)

![AI model and registered IP administration](docs/images/admin-controls.png?raw=1)

</details>

## Scoring Policy

Python calculates at most 80 points:

| Category | Maximum |
| --- | ---: |
| Sensor finding severity | 20 |
| Behavior and time correlation | 20 |
| Cached threat intelligence | 20 |
| Registered IP importance and traffic direction | 10 |
| Suricata-Zeek corroboration | 10 |

MITRE ATT&CK remains descriptive context and does not contribute points. The AI adjustment is independently clamped to `-10..+10`, giving new cases an effective final range of `0..90`. Existing thresholds remain provisional pending sensitivity testing:

- `0-29`: Safe
- `30-69`: Human Review Required
- `70-84`: High Risk
- `85-90`: Dangerous

Materially disputed sensor evidence forces Human Review Required. VirusTotal is post-AI verification evidence and never changes the score or lowers a classification.

## Prerequisites

Recommended and tested OS:

```text
Ubuntu 22.04 or newer
```

Required system components:

```text
python3 (3.10 or newer recommended)
python3-venv
python3-pip
suricata
suricata-update
zeek
zeekctl
zkg
iproute2
curl
git
```

Zeek is required, not an optional worker. Bootstrap warns before continuing on Ubuntu releases older than 22.04 because the supported Zeek package path may not work reliably there.

Python's standard library includes the `sqlite3` module. The application creates and migrates `security_vm.db`; the optional SQLite CLI is useful for manual inspection but is not required for application database access.

The following packages are installed into the virtual environment by `pip install -r requirements.txt`:

| Python package | Purpose |
| --- | --- |
| FastAPI | Dashboard and administrative API |
| Uvicorn | Local ASGI server |
| PyYAML | Configuration loading and updates |
| Requests | AI-service and threat-intelligence HTTP clients |

## Installation

```bash
git clone https://github.com/chlee31/security-vm.git
cd security-vm
git switch dev

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp config.yaml.example config.yaml
python -m app.bootstrap
```

Bootstrap checks the OS and required tools, initializes SQLite, configures the AI endpoint, guides Zeek interface and JSON-log setup, and can enable matching Community IDs. Reviewed Zeek packages can be installed through `zkg` when approved. Interface names are detected from the host instead of assuming `ens33`, `ens37`, or `eth0`.

## Start Everything

With the virtual environment active:

```bash
python -m app.main run-all --config config.yaml
```

This command starts or checks:

1. Suricata service and EVE ingestion
2. Required Zeek service and JSON-log ingestion
3. Configured threat-intelligence refresh worker
4. Dashboard API

Normal worker output is quiet; errors and unexpected exits are printed in the terminal.

The safe dashboard default is:

```text
http://127.0.0.1:8000
```

For access from a trusted management network:

```bash
python -m app.main run-all --config config.yaml --host 192.168.57.134 --port 8000
```

Binding to `0.0.0.0` exposes the unauthenticated prototype on every interface and prints a warning. Use it only on a controlled lab/management network with host firewall restrictions.

Stop the launcher and its child workers with `Ctrl+C` before shutting down the lab or AI host.

## Sensor Checks

```bash
sudo systemctl status suricata --no-pager
python -m app.main zeek-status --config config.yaml
sudo /opt/zeek/bin/zeekctl status
```

Confirm data is arriving:

```bash
sudo tail -f /var/log/suricata/eve.json
sudo tail -f /opt/zeek/logs/current/conn.log
```

The dashboard's Zeek page shows runtime state, log counts, TLS, DNS, HTTP, file observations, checkpoints, and recent records.

Suricata ingestion stores a path/inode/offset checkpoint and resumes from the last event acknowledged after case assessment completes. It detects EVE rotation or truncation and uses a canonical event fingerprint to prevent duplicate alert rows during replay. On a new database, `suricata.start_position: end` ignores historical EVE content; set it to `beginning` only when an intentional replay is required.

## Community ID

Community ID is the strongest direct way to correlate the same bidirectional flow across Suricata and Zeek. Both sensors must use seed `0`:

```bash
sudo ./scripts/enable_community_id.sh
```

When Community ID is unavailable, the platform falls back to Zeek UID relationships and bidirectional flow/time matching. Related multi-connection behavior can still be grouped into a developing case using conservative same-sensor rules.

The default `correlation-v1` windows are 10 seconds for cross-sensor flow matching, 300 seconds for repeated same-sensor behavior, and 120 seconds for bounded Zeek context. Correlation values shown in the case view are rule strengths, not calibrated probabilities. Both the windows and strengths are configurable in `config.yaml` and require experimental sensitivity testing.

Detection-type labels are conservative keyword rules. Explicit scan, DNS-tunnelling, beaconing/C2, and brute-force language receives a specialized label; generic DNS, SYN, login, and SSH references remain `unknown`. This taxonomy is an implementation heuristic, not a trained or validated classifier.

## Investigation Cases

Every case receives a UID such as `CASE-20260717-000123`. Its investigation page contains:

- all linked Suricata and Zeek findings;
- exact timestamps and network endpoints;
- correlation method, configured rule strength, and Community ID when available;
- bounded Zeek connection/protocol context;
- repeated-activity and periodicity summary;
- registered IP role and traffic-direction context;
- provider-by-provider threat-intelligence results;
- deterministic score breakdown;
- AI case explanation and evidence boundaries;
- optional side-by-side responses from three configured AI profiles;
- VirusTotal verification records;
- analyst review history and controls.

The **Reassess Case** button makes one explicit AI request using the latest stored evidence. **Refresh VirusTotal** refreshes eligible global IPs only and does not automatically trigger another AI call.

### Three-Model Comparison

Create at least three active AI profiles under `/admin`, then choose exactly three in **Comparison profiles**. From a case investigation, select **Run Three-Model Comparison**. Python freezes one evidence package and sends it to the three profiles sequentially, waiting for each response before starting the next request.

All three responses appear directly on the case investigation page with model names, profile UIDs, summaries, six-part explanations, ordered investigation steps, and expandable raw responses. Open the run in `/compare` to select the most useful response, mark a tie, or reject all responses. The comparison scorecard reports which profile has been selected most often.

Model comparison is an evaluation feature. Candidate adjustments do not stack, do not replace the official case assessment, and do not alter Python's recorded classification or response.

## Threat Intelligence

Configure providers under `/admin` in the Threat Intelligence tab. Supported cached/bulk sources include ThreatFox, URLhaus, SSLBL, Spamhaus DROP, OpenPhish Community, IPsum, Feodo Tracker, and cached OTX results.

For each bounded case, Python extracts IOC-like values from related Zeek records and records which Zeek log, timestamp, UID, and source/destination IPs produced them. These observables are matched locally against active cached providers before scoring and AI review. Routine case processing does not make one remote API request per observable.

VirusTotal is queried only after the AI classifies a case as Dangerous, or after a reassessment becomes Dangerous. Private, loopback, link-local, multicast, reserved, and `100.64.0.0/10` addresses are never queried. API keys are masked from API responses and must never be committed.

## AI Service

The AI endpoint is configured in `config.yaml` or `/admin`:

```yaml
ai_model:
  host: http://127.0.0.1:11434
  model: llama3.1:8b
  provider: ollama
```

Profiles are retained for repeatable model experiments. Each AI report stores provider, model, profile UID, run UID, prompt version/hash, elapsed time, classification, confidence, bounded adjustment, and the six-part explanation.

Saved profiles can be deleted from `/admin`. Historical reports and comparison results keep their recorded model identity. Deleting a comparison profile removes it from future three-model runs, and deleting the selected runtime profile automatically selects another active profile. The final saved profile cannot be deleted until a replacement exists.

Every AI response must also return two to five ordered next steps. Each step should name the observable or sensor evidence to inspect and the question the analyst should answer; generic advice such as only "investigate further" is rejected by the prompt contract.

If an Ollama-compatible service is on a Windows host reached over Tailscale, it must listen beyond localhost. In Administrator PowerShell:

```powershell
setx OLLAMA_HOST "0.0.0.0:11434" /M
taskkill /IM ollama.exe /F
netsh advfirewall firewall add rule name="Allow Ollama 11434" dir=in action=allow protocol=TCP localport=11434
tailscale serve --bg --tcp=11434 tcp://localhost:11434
tailscale serve status
```

Then test from Security VM:

```bash
curl http://YOUR_TAILSCALE_IP:11434/api/tags
```

## Development Lab Routing

The intended real deployment is passive monitoring from a switch SPAN/mirror port. Bootstrap retains an optional **development-only** routing wizard so isolated test VMs can send observable traffic through the Security VM. It configures netplan, IPv4 forwarding, and NAT only when explicitly selected.

Do not describe this lab arrangement as the product architecture. In production, the monitoring interface should receive copied traffic and should not become the organization's gateway or firewall.

## Testing

```bash
source venv/bin/activate
python -m unittest discover -s tests -v
python -m compileall app
```

Suggested evaluation scenarios:

1. Repeated Suricata-only scan activity
2. Suricata-Zeek Community ID correlation
3. Zeek DNS/HTTP/TLS context retrieval
4. Registered IP and threat-intelligence enrichment
5. AI factual accuracy and unsupported-claim rate

## Security Notes

- `config.yaml`, databases, logs, and API keys must not be committed.
- The dashboard has no built-in authentication; bind it conservatively.
- The AI never executes system-response commands.
- Network metadata cannot prove endpoint process, user identity, or decrypted payload content.
- Analyst judgment remains required for consequential response decisions.

# Security VM

Security VM is an AI-assisted network security monitoring and investigation research prototype. It combines Suricata findings and Zeek network metadata into centralized cases, adds threat-intelligence context, and asks locally configured AI models to explain the evidence and recommend investigation steps.

Python retains control of correlation, final action mapping, data handling, and safety boundaries. AI output is advisory and receives bounded structured evidence without API keys or raw packet captures.

> [!IMPORTANT]
> **AI input is limited by tokens, not by a 4 KB file limit.** Security VM does not upload Suricata logs, Zeek logs, databases, or packet-capture files directly to the model. Python selects relevant records, normalizes them into structured JSON text, applies documented record and field limits, and sends that bounded evidence inside the prompt.
>
> The installed Llama 3.1 and Llama 3.2 models advertise context windows of approximately 131,072 tokens, while the current NVIDIA Nemotron model metadata advertises 1,048,576 tokens. Security VM intentionally configures a much smaller `num_ctx: 8192` operational window to control VRAM/RAM use, latency, and request size. The 8,192-token window includes both input and generated output; with `num_predict: 1024`, Python reserves up to 1,024 tokens for the response and budgets approximately 7,168 for the prompt. Model-advertised limits are capabilities, not the limits selected for this deployment.
>
> Every new request records the exact prompt, normalized evidence, omissions, configured context, and Ollama's measured `prompt_eval_count` in SQLite so an analyst can verify what was actually submitted and processed.
> 
> For any questions and inqueries Contact: chlee31@myseneca.ca (ChaeHyeon Lee or Marino Lee)

## Current Scope

Security VM currently provides:

- passive network evidence collection from required Suricata and Zeek sensors;
- deterministic case construction and evidence-preserving SQLite storage;
- cached threat-intelligence enrichment and post-AI VirusTotal verification;
- qualitative AI-assisted classification, evidence summaries, and human review controls;
- sequential multi-model comparison using one frozen evidence package;
- controlled temperature/seed stability and missing-evidence experiments.

The project is an **analysis platform**. It is not an endpoint agent, decrypted-payload inspection system, production firewall, autonomous response engine, or replacement for analyst judgment. The intended deployment uses copied traffic from a SPAN or mirror port.

## Workflow

```text
Mirrored network traffic
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
 Cached threat-intelligence enrichment
             |
             v
 Bounded qualitative AI explanation and classification
             |
             v
 Python safety rules + optional VirusTotal verification
             |
             v
 Centralized investigation + analyst review
             |
             v
 Optional sequential multi-model comparison
```

See [SECURITY_VM_WORKFLOW.md](docs/SECURITY_VM_WORKFLOW.md) for the detailed
data flow and [CODE_WALKTHROUGH.md](docs/CODE_WALKTHROUGH.md) for a
module-by-module explanation of prompt construction, context budgeting, request
auditing, and response handling.

For a professor-facing map of every major module and the settings that are safe
to customize, see [CODE_AND_CONFIGURATION_GUIDE.md](docs/CODE_AND_CONFIGURATION_GUIDE.md).

## AI Data Transfer: Prompt, Not File Upload

Security VM does **not** upload Suricata files, Zeek files, SQLite databases, packet captures, or threat-intelligence datasets to the AI service. Those records remain on the Security VM.

For each assessment, Python:

1. reads the locally stored case and sensor records;
2. selects and bounds the relevant evidence;
3. normalizes that evidence into a structured JSON object;
4. embeds the object with the review instructions in one complete text prompt;
5. sends the prompt to the Ollama-compatible `/api/generate` endpoint; and
6. requires the model to return a response matching a JSON schema.

The HTTP request is conceptually:

```json
{
  "model": "llama3.1:8b",
  "prompt": "Review instructions followed by the normalized evidence JSON",
  "stream": false,
  "format": "Security VM structured-response JSON schema",
  "options": {
    "num_ctx": 8192,
    "num_predict": 1024
  }
}
```

This JSON is the API message envelope, not an attached JSON file. Tailscale provides the encrypted network route to a remote model host but does not change what is sent. The model receives only the bounded prompt and output contract. Python then validates and stores the returned JSON response. The investigation audit exposes the exact prompt, normalized package, omissions, request settings, measured input-token count, and returned response.

## Core Features

- Required live Suricata and Zeek sensors
- Original Suricata EVE alerts and Zeek JSON records stored in SQLite
- Stable case, Suricata-event, and Zeek-event UIDs
- Community ID, Zeek UID, bidirectional flow, timestamp, and repeated-behavior correlation
- Conservative same-sensor grouping for scans, DNS tunneling, beaconing, brute force, and repeated identical findings
- Bounded Zeek context from `conn`, `dns`, `http`, `ssl`, `notice`, `weird`, `files`, `ssh`, and `x509` logs
- Zeek-derived IPs, DNS answers, domains, URLs, TLS/certificate fingerprints, JA3 values, file hashes, and SSH host keys matched against active cached threat-intelligence feeds with source-log and endpoint provenance
- Cached threat-intelligence providers plus post-AI VirusTotal verification
- Evidence-grounded AI explanation of who, what, when, where, why, how, and next steps
- Exact per-request AI audit records with prompt/evidence/response hashes, source lineage, and an explicit omission manifest
- Analyst confirmation, override, notes, and tuning labels
- Manual dashboard refresh so the page does not jump while an analyst is reading

## Interface

### Dashboard Overview

![Security VM dashboard overview](docs/images/dashboard-overview.png?raw=1)

The dashboard summarizes sensor findings, centralized cases, outcome queues, encrypted-traffic metadata, combined alerts, and Zeek health. Data changes only when the analyst selects **Refresh**.

### Case Investigation

![Centralized case investigation](docs/images/case-investigation.png?raw=1)

Each case has a stable UID and brings together timestamps, sensor findings, network endpoints, threat intelligence, AI explanations, reassessment, and analyst feedback. Expandable sensor records show the original Suricata or Zeek JSON, parsed endpoints and ports, source table/row, event UID, field lineage, and raw-record hash.

The dashboard also links to Zeek telemetry, where sensor state, ingestion checkpoints, log volumes, and protocol metadata from connection, DNS, HTTP, TLS, file, notice, weird, SSH, and X.509 records can be reviewed.

## Classification Policy

The model reviews bounded Suricata, Zeek, correlation, and threat-intelligence evidence and returns one of three qualitative classifications:

- `Safe`
- `Analyst Review Required`
- `Dangerous`

Python validates the structured response and maps those classifications to `log_only`, `human_review`, or `escalate`. Invalid or missing classifications, Low-confidence model conclusions, and materially disputed Suricata and Zeek evidence are routed to Analyst Review Required. The internal `human_review` action name is retained for database and API compatibility. VirusTotal is separate post-AI verification for Dangerous results; it never supplies points and a no-detection result never lowers the classification.

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

## Suricata Installation and Setup

Suricata is a required sensor, but its package installation, capture interfaces,
rules, and system service are managed outside this Python application. Follow
the [official Suricata Quickstart Guide](https://docs.suricata.io/en/latest/quickstart.html)
to install Suricata, select the correct monitoring interface or interfaces,
install ET Open rules with `suricata-update`, and enable EVE JSON output.

Before starting Security VM, confirm that:

- Suricata monitors the intended interfaces from `/etc/suricata/suricata.yaml`.
- `/var/log/suricata/eve.json` exists and receives alert records.
- `suricata -T -c /etc/suricata/suricata.yaml` succeeds.
- The application user can read the EVE JSON file.

For cross-sensor correlation, complete the [Community ID setup](#community-id)
after both Suricata and Zeek are installed:

```bash
sudo ./scripts/enable_community_id.sh
```

The helper backs up both sensor configurations, configures matching Community
ID seed `0`, validates the configurations, restarts Suricata, and deploys Zeek.
Suricata interface and rule settings remain administrator-managed system
configuration and are not generated by bootstrap.

## Start Everything

With the virtual environment active:

```bash
python -m app.main run-all --config config.yaml
```

`run-all` starts three required processing workers in addition to the
dashboard: Suricata ingestion, Zeek ingestion, and AI assessment. Sensor
readers store and checkpoint evidence immediately. The AI worker processes
persisted cases separately, one case at a time, so a slow model response
cannot make Suricata or Zeek ingestion fall behind.

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
export SECURITY_VM_ADMIN_USER=admin
read -rsp "Security VM admin password: " SECURITY_VM_ADMIN_PASSWORD
export SECURITY_VM_ADMIN_PASSWORD
echo
python -m app.main run-all --config config.yaml --host 192.168.57.134 --port 8000
```

`SECURITY_VM_ADMIN_PASSWORD` is required for `/admin` and every `/api/admin/*`
endpoint. The browser requests HTTP Basic credentials once; the default
username is `admin`. The password remains in the launcher environment and is
not written to YAML or SQLite.

The Admin **Runtime Console** refreshes every two seconds and displays sanitized
AI request phases plus recent sensor, correlation, enrichment, and worker
events. It shows prompt size, estimated token count, request timeout, elapsed
wait, parse state, safe errors, and live `run-all` process heartbeats, but never
API keys or complete prompt text.

Binding to `0.0.0.0` still exposes the main research dashboard without built-in
authentication and prints a warning. Use it only on a controlled lab or
management network with host firewall restrictions.

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

Suricata ingestion stores a path/inode/offset checkpoint and resumes from the
last event durably stored and correlated in SQLite. AI assessment happens in a
separate worker and does not delay this checkpoint. The reader detects EVE
rotation or truncation and uses a canonical event fingerprint to prevent
duplicate alert rows during replay. On a new database,
`suricata.start_position: end` ignores historical EVE content; set it to
`beginning` only when an intentional replay is required.

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
- provider-by-provider threat-intelligence results;
- qualitative classification, confidence, and evidence-based explanation;
- AI case explanation and evidence boundaries;
- optional side-by-side responses from any selected active AI profiles;
- VirusTotal verification records;
- analyst review history and controls.

The **Reassess Case** button makes one explicit AI request using the latest stored evidence. **Refresh VirusTotal** refreshes eligible global IPs only and does not automatically trigger another AI call.

### Controlled LLM Experiments

Open `/compare` to queue a baseline comparison for a stored case. Select any
number of active AI profiles, or select all active profiles. The API returns a
comparison UID immediately; the `experiment-worker` started by `run-all`
executes requests sequentially in the background. Responses use dynamic blind
labels such as `R01`, `R02`, and `R03`. Model identities remain hidden until a
winner, tie, or reject-all review is recorded.

Baseline requests use `temperature: 0`, seed `42`, `num_ctx: 8192`, and
`num_predict: 1024`. Python freezes the exact prompt, normalized evidence,
generation settings, selected profile order, and Ollama model digest before
execution. The dashboard verifies prompt, evidence, and generation-option
equality across every successful response.

For cases with repeated sensor events, Python keeps every raw finding in SQLite and the case evidence view but sends the models a bounded recurrence summary. Repeated rows are grouped by sensor, finding name/type, endpoints, destination port, and protocol. The model receives occurrence counts, first/last timestamps, and representative event UIDs, which prevents dozens of duplicate alerts from obscuring distinct evidence.

All successful anonymized responses appear on the case page and `/compare`.
After review, the workspace reveals the selected model identity. **Use Selected
Response on Case** changes only the displayed explanation; it does not overwrite
the original AI report, candidate, request audit, sensor evidence, or analyst
decision.

The comparison export contains one CSV/JSON row per model candidate, including
model build metadata, request controls, hashes, token metrics, timing, parsed
response fields, raw response, and review outcome.

Use `/experiments/stability` to rerun every successful baseline candidate with
controlled temperature and seed combinations. Use
`/experiments/missing-evidence` after selecting a baseline winner to test that
winner against explicit evidence-removal masks. Both pages queue durable
background jobs, show control and variant responses together, accept manual
evaluation scores, and export one research row per experimental response.

Run the worker separately only when `run-all` is not being used:

```bash
python -m app.main experiment-worker --config config.yaml
```

See [docs/llm-experiments.md](docs/llm-experiments.md) for the experimental
controls, database records, workflow, and CSV columns.

Model comparison is an evaluation feature. Promoting a winner changes only which AI explanation is presented on the case page. Candidate classifications do not replace the official case assessment and do not alter Python's recorded action.

## Threat Intelligence

Configure providers under `/admin` in the Threat Intelligence tab. Supported cached/bulk sources include ThreatFox, URLhaus, SSLBL, Spamhaus DROP, OpenPhish Community, IPsum, Feodo Tracker, and cached OTX results.

For each bounded case, Python extracts IOC-like values from related Zeek records and records which Zeek log, timestamp, UID, and source/destination IPs produced them. These observables are matched locally against active cached providers before AI review. Routine case processing does not make one remote API request per observable.

VirusTotal is queried only after the AI classifies a case as Dangerous, or after a reassessment becomes Dangerous. Private, loopback, link-local, multicast, reserved, and `100.64.0.0/10` addresses are never queried. API keys are masked from API responses and must never be committed.

## AI Service

The AI endpoint is configured in `config.yaml` or `/admin`:

```yaml
ai_model:
  host: http://127.0.0.1:11434
  model: llama3.1:8b
  provider: ollama
  num_ctx: 8192
  num_predict: 1024
```

Profiles are retained for repeatable model experiments. Each AI report stores provider, model, profile UID, run UID, prompt version/hash, elapsed time, classification, confidence, and the six-part explanation.

`num_ctx` is the total token window available to the request and response; it is not a byte or file-size setting. `num_predict` reserves the maximum generated response length from that window. Increasing either value can materially increase memory use and latency. Security VM therefore keeps the operational context below the models' advertised maximum and compacts evidence before each request.

Every new model request also creates an `ai_run_audits` row containing the exact prompt, exact normalized evidence package, full response, safe request settings, source-record map, byte/character counts, SHA-256 values, and every Python omission or truncation. The investigation page exposes this proof under **AI Request and Data Lineage**. See [docs/ai-evidence-audit.md](docs/ai-evidence-audit.md) for the complete data path and review procedure.

Saved profiles can be deleted from `/admin`. Historical reports and comparison results keep their recorded model identity. Deleting a comparison profile removes it from future comparison runs, and deleting the selected runtime profile automatically selects another active profile. The final saved profile cannot be deleted until a replacement exists.

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

## Network Placement

Security VM is a passive monitoring system. Connect its monitoring interface to
a switch SPAN or mirror destination and configure Suricata and Zeek to observe
that interface. Bootstrap does not configure routing, NAT, packet filtering, or
client gateways.

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
4. Threat-intelligence enrichment
5. AI factual accuracy and unsupported-claim rate

## Security Notes

- `config.yaml`, databases, logs, and API keys must not be committed.
- The dashboard has no built-in authentication; bind it conservatively.
- The AI never executes system-response commands.
- Network metadata cannot prove endpoint process, user identity, or decrypted payload content.
- Analyst judgment remains required for consequential response decisions.

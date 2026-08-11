# Security VM Code and Configuration Guide

This guide is intended for a code demonstration or project defense. It explains
what each major part of Security VM does, where configuration values come from,
which settings are safe to change, and which files should normally be left
alone.

## The Short Explanation

Security VM has five main stages:

1. **Suricata and Zeek observe network traffic.**
2. **Python reads and normalizes their JSON records.**
3. **Python stores original evidence in SQLite and correlates related findings
   into a case.**
4. **Python adds cached threat-intelligence context and builds a bounded text
   prompt containing normalized JSON evidence.**
5. **An Ollama-compatible model returns structured JSON. Python validates and
   stores the response for analyst review.**

The model does not read files, query SQLite, or access API keys directly.
Python controls what evidence is selected and sent.

## Files You Will Change Most Often

| File | Change it when... |
|---|---|
| `config.yaml` | Changing interfaces, log paths, AI endpoint/model, context size, temperature, seed, correlation windows, or threat-intelligence settings |
| `config.yaml.example` | Changing the documented defaults distributed to new users |
| `app/ai_client.py` | Changing prompt instructions, evidence limits, output schema, or model request behavior |
| `app/normalizer.py` | Changing how Suricata records are converted into common fields or broad behavior labels |
| `app/zeek_normalizer.py` | Changing which Zeek fields are retained for each log type |
| `app/sensor_fusion.py` | Changing the common representation shared by Suricata and Zeek findings |
| `app/database.py` and `sql/schema.sql` | Adding persisted fields or database tables; use migrations and preserve existing data |
| `app/dashboard.py` | Adding or changing API endpoints |
| `static/*.html`, `static/*.js`, `static/styles.css` | Changing pages, browser behavior, or visual styling |

`config.yaml` is the normal place for deployment-specific changes. Avoid
hard-coding an IP address, interface, model, or API key in Python.

## Configuration Loading

`app/config.py` defines `DEFAULT_CONFIG`. `load_config()` reads `config.yaml`
and recursively merges the user's values over those defaults. This means a
short `config.yaml` is valid: omitted settings use the Python defaults.

`config.yaml.example` is a template. The running application reads
`config.yaml`, not the example file.

After changing `config.yaml`, restart `run-all` unless the setting was saved
through an Admin API that explicitly reloads it. Sensor interface, worker, and
AI request settings should be treated as restart-required.

## What Bootstrap Actually Does

Run bootstrap from the repository with the virtual environment active:

```bash
python -m app.bootstrap
```

`app/bootstrap.py` performs these steps:

1. Reads `/etc/os-release` and recommends Ubuntu 22.04 or newer for the tested
   Zeek installation path.
2. Asks for the AI machine IP address, API port, and exact model name.
3. Checks for `ip`, Suricata, SQLite CLI, Zeek, `zeekctl`, and `zkg`.
4. Offers to install missing apt packages and, on supported Ubuntu versions,
   Zeek from its official OBS repository.
5. Discovers real interface names using `ip -j addr show`; it does not assume
   that every machine uses `ens33`, `ens37`, or `eth0`.
6. Requires the user to select the interface Zeek should monitor.
7. Offers to configure Zeek JSON logs, Community ID support, and reviewed Zeek
   packages.
8. Offers to update `config.yaml` with the AI endpoint/model and Zeek settings.
9. Creates or migrates the configured SQLite database.
10. Calls the model service `/api/tags` endpoint to verify reachability and
    report which models are available.

Bootstrap deliberately asks before writing privileged Zeek files or updating
an existing `config.yaml`. It creates backups through the Community ID helper
before changing the Suricata and Zeek Community ID configuration.

Bootstrap does **not**:

- assign a static IP address to Ubuntu;
- create a Netplan file;
- configure NAT, forwarding, masquerading, or firewall enforcement;
- make the host a router;
- select the dashboard's bind address; or
- install a permanent dashboard system service.

Those omissions are intentional because the current evaluated deployment is a
passive monitoring and investigation platform using mirrored traffic.

## Changes and When They Take Effect

| Change | Where | Takes effect |
|---|---|---|
| AI host or model | `config.yaml` or Admin AI profile | New requests after workers restart; Admin selection updates configuration, but restart is safest before experimental collection |
| Temperature, seed, context, output limit | `config.yaml` | New requests after AI worker restart |
| Threat-intelligence provider/API key | Admin or `config.yaml` | After saving and refreshing the provider; restart scheduled worker if edited manually |
| Zeek interface | `config.yaml` **and** Zeek `node.cfg` | After `zeekctl deploy` and application restart |
| Zeek context log list/window | `config.yaml` | After application restart |
| Suricata EVE path | `config.yaml` | After ingestion restart |
| Suricata capture interface/rules | `/etc/suricata/suricata.yaml` | After `suricata -T` validation and Suricata restart |
| Dashboard bind address/port | `--host` and `--port` command options | Immediately on the next dashboard start |
| Ubuntu interface IP address | `/etc/netplan/*.yaml` | After `netplan try/apply`; persists across reboot |

## Dashboard Address: Bind Address Versus Machine Address

The dashboard does not own an IP address. Ubuntu owns IP addresses on network
interfaces; Uvicorn only chooses which existing address to listen on.

These commands have different meanings:

```bash
# Only this computer can connect.
python -m app.main run-all --config config.yaml --host 127.0.0.1 --port 8000

# Listen on one existing Ubuntu management address.
python -m app.main run-all --config config.yaml --host 192.168.57.134 --port 8000

# Listen on every IPv4 address currently assigned to Ubuntu.
python -m app.main run-all --config config.yaml --host 0.0.0.0 --port 8000
```

`0.0.0.0` is a wildcard bind address. A browser cannot navigate to it as the
Security VM's permanent address. Users browse to a real address such as
`http://192.168.57.134:8000`.

Check the available addresses before selecting `--host`:

```bash
ip -br address
ip route
```

The safest remote setup is to bind to one trusted management-interface address,
not `0.0.0.0`. Main research pages are not protected by production-grade
authentication. Admin Basic authentication does not make every page safe for
Internet exposure.

### Make the Ubuntu management IP permanent

First identify the management interface and current default gateway:

```bash
ip -br address
ip route show default
ls -l /etc/netplan
```

Back up the existing Netplan files before editing them. A typical static
management-interface example is:

```yaml
# /etc/netplan/60-security-vm-management.yaml
network:
  version: 2
  ethernets:
    ens33:
      dhcp4: false
      addresses:
        - 192.168.57.134/24
      routes:
        - to: default
          via: 192.168.57.2
      nameservers:
        addresses:
          - 192.168.57.2
          - 1.1.1.1
```

The interface, address, prefix, gateway, and DNS servers above are examples;
replace them with values valid for the user's management network. Do not add a
default gateway to a passive SPAN/mirror capture interface.

Validate safely from the local console:

```bash
sudo netplan generate
sudo netplan try
sudo netplan apply
ip -br address
ip route
```

`netplan try` can roll back if connectivity is lost. Avoid applying remote
network changes without console access.

After Ubuntu owns the permanent address, start Security VM on that address:

```bash
python -m app.main run-all \
  --config config.yaml \
  --host 192.168.57.134 \
  --port 8000
```

The address is permanent because Netplan assigns it after reboot. The `--host`
argument still needs to be supplied each time Security VM starts unless a
service or launcher stores that command.

### Make dashboard startup persistent

For a lab demonstration, the dashboard API alone can be made persistent with a
systemd unit whose `ExecStart` contains the tested dashboard command. Example:

```ini
# /etc/systemd/system/security-vm.service
[Unit]
Description=Security VM dashboard API
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=router1
WorkingDirectory=/home/router1/Documents/security-vm
Environment=SECURITY_VM_ADMIN_USER=admin
EnvironmentFile=-/etc/security-vm/admin.env
ExecStart=/home/router1/Documents/security-vm/venv/bin/python -m app.main dashboard --config /home/router1/Documents/security-vm/config.yaml --host 192.168.57.134 --port 8000
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Store the admin password in a root-readable environment file instead of the
unit or Git repository:

```bash
sudo install -d -m 0750 /etc/security-vm
sudo sh -c 'printf "%s\n" "SECURITY_VM_ADMIN_PASSWORD=replace-with-a-strong-password" > /etc/security-vm/admin.env'
sudo chmod 0600 /etc/security-vm/admin.env
sudo systemctl daemon-reload
sudo systemctl enable --now security-vm
sudo systemctl status security-vm
```

This unit is an operational example, not currently installed by bootstrap. It
keeps the web API available but does not start ingestion or AI workers. Run the
normal `run-all` command for the complete platform.

`run-all` performs interactive `sudo -v` authentication before managing the
required Suricata and Zeek sensors. It therefore should not be copied into an
unattended user service. A complete boot-time service requires a deliberately
designed service account, sensor permissions, and narrowly scoped privilege
policy; running the entire project as root is not recommended.

## Annotated `config.yaml`

### System

```yaml
system:
  mode: analysis
  retention_days: 7
```

- `mode`: The current project is a passive analysis platform. `app/config.py`
  normalizes this to `analysis`; it is not a firewall/prevention switch.
- `retention_days`: Intended retention period for application records. Confirm
  cleanup behavior before relying on it as a compliance retention control.

### Suricata

```yaml
suricata:
  eve_json_path: /var/log/suricata/eve.json
  fast_log_path: /var/log/suricata/fast.log
  start_position: end
```

- `eve_json_path`: File followed by `app/suricata_reader.py`. Change this if
  Suricata writes EVE JSON somewhere else.
- `fast_log_path`: Optional human-readable Suricata log path.
- `start_position`: `end` avoids replaying the complete EVE file when no saved
  checkpoint exists. Checkpoints subsequently preserve inode and byte offset.

Suricata's monitored interface and rule files are controlled by the Suricata
service configuration, usually `/etc/suricata/suricata.yaml`, not by this
application field.

### SQLite

```yaml
database:
  path: security_vm.db
```

- `path`: SQLite database used by all workers and the dashboard. A relative
  path is relative to the directory from which the application is started.
- Do not point multiple independent Security VM installations at the same
  SQLite file over a network filesystem.
- Schema creation and migrations run through `app/database.py::init_db`.

### Zeek

```yaml
zeek:
  enabled: true
  interface: ens37
  log_directory: /opt/zeek/logs/current
  archive_directory: /opt/zeek/logs
  json_logs: true
  ingest_notice: true
  ingest_weird: true
  context_logs:
    - conn
    - dns
    - http
    - ssl
    - files
    - notice
    - weird
    - ssh
    - x509
```

- `enabled`: Must remain `true`; Zeek is a required sensor in this project.
- `interface`: Interface Zeek monitors. Use `ip -br link` to find the correct
  name. In a router lab this is often the internal or mirrored interface.
- `log_directory`: Current Zeek JSON logs read by `app/zeek_ingest.py`.
- `archive_directory`: Rotated Zeek log location.
- `json_logs`: Must agree with Zeek's actual output format.
- `ingest_notice` and `ingest_weird`: Include those event types in ingestion.
- `context_logs`: Zeek logs that may provide supporting context to a case.
  Removing one prevents that log type from contributing context.
- `community_packages`: Reviewed `zkg` packages offered by bootstrap.
- `package_install_enabled`: Controls whether automated package installation is
  permitted. Keep it false unless the packages have been reviewed.

Run these checks after changing Zeek settings:

```bash
python -m app.main zeek-status --config config.yaml
sudo /opt/zeek/bin/zeekctl check
sudo /opt/zeek/bin/zeekctl deploy
```

### Correlation

```yaml
correlation:
  policy_version: correlation-v1
  sensor_time_tolerance_seconds: 10
  same_sensor_window_seconds: 300
  zeek_context_window_seconds: 120
  zeek_context_limit: 100
```

- `policy_version`: Label stored with correlation output for traceability.
- `sensor_time_tolerance_seconds`: Maximum time difference used for close
  Suricata/Zeek flow correlation when stronger identifiers are unavailable.
- `same_sensor_window_seconds`: Window for grouping repeated similar findings
  from one sensor.
- `zeek_context_window_seconds`: Time around a case searched for supporting
  Zeek records.
- `zeek_context_limit`: Maximum Zeek rows retrieved before AI-specific
  compaction applies.
- `strengths`: Descriptive confidence values for correlation methods. They are
  not the retired incident risk score.

Changing windows changes case membership and must be documented as a research
method change. Test it against labeled traffic before changing production data.

### Primary AI Model

```yaml
ai_model:
  host: http://100.99.223.100:11434
  model: llama3.1:8b
  provider: ollama
  active_profile_uid: ''
  timeout_seconds: 90
  num_predict: 1024
  num_ctx: 8192
  temperature: 0.0
  seed: 42
```

- `host`: Base URL of the Ollama-compatible API. Examples:
  - Local: `http://127.0.0.1:11434`
  - LAN/Tailscale: `http://100.99.223.100:11434`
  Do not append `/api/generate`; Python adds it.
- `model`: Exact name returned by `curl http://HOST:11434/api/tags` or
  `ollama list` on the model host.
- `provider`: Research label stored with the response. The current transport
  remains Ollama-compatible HTTP even if the model family is NVIDIA, Gemma,
  DeepSeek, or Qwen.
- `active_profile_uid`: Stable database profile identifier. Usually set through
  Admin profile selection rather than typed manually.
- `timeout_seconds`: Maximum HTTP request time. Increase it for slow models, but
  first confirm the model host is healthy.
- `num_ctx`: Total request context shared by input and generated output.
- `num_predict`: Maximum output tokens reserved inside `num_ctx`.
- `temperature`: Sampling variation. Lower values are more repeatable; higher
  values produce more varied wording. Use `0.0` for the experiment control.
- `seed`: Pseudorandom seed supplied to Ollama. The same seed improves
  repeatability but does not guarantee byte-identical output across different
  models, versions, hardware, or server builds.

Approximate prompt budget:

```text
available input = num_ctx - num_predict
7168 tokens = 8192 - 1024
```

`app/ai_client.py::ask_ai_model` sends all four request options to
`POST /api/generate`. These values apply even when the model runs remotely over
Tailscale. The Ollama desktop context slider does not replace the explicit
per-request `num_ctx` sent by Python.

There are three distinct places where temperature and seed can come from:

1. Normal case analysis uses `ai_model.temperature` and `ai_model.seed` from
   `config.yaml`.
2. Case reassessment uses the same `ai_model.temperature` and `ai_model.seed`
   values from `config.yaml` as normal case analysis.
3. Model-comparison control requests use `CONTROL_OPTIONS` near the top of
   `app/ai_comparison.py`. This is an advanced research control and should agree
   with the written methodology and its regression tests.
4. Temperature/seed experiments use the values entered on the experiment page;
   those intentionally override the baseline for each queued variation.

Restart `run-all` after changing `config.yaml`. Code-level research controls
also require a restart and should not be changed midway through one dataset.

Test the endpoint:

```bash
curl http://100.99.223.100:11434/api/tags
```

### Reassessment and Comparison

```yaml
ai_reassessment:
  enabled: true
  include_suricata: true
  include_zeek: true
  include_threat_intel: true

ai_comparison:
  profile_uids: []
  sequential: true
```

- Reassessment switches control which evidence categories are rebuilt for a
  case reassessment.
- `profile_uids` selects saved model profiles used in comparison runs. The
  Admin interface is safer than manually copying UIDs.
- `sequential: true` sends one model request at a time to limit GPU memory load.
- Comparison responses use one frozen prompt and evidence snapshot. Their
  prompt and evidence hashes should match within a run.

### Controlled Experiments

```yaml
ai_experiments:
  worker_poll_seconds: 1.0
```

- The experiment worker polls its durable SQLite queue at this interval.
- Temperature and seed variants are chosen in the experiment page and stored
  per task; they do not overwrite the primary `ai_model` settings.
- Experiments use analyst-selected comparison winners as baselines.

### Threat Intelligence

```yaml
threat_intel:
  cache_ttl_hours: 24
  providers:
    threatfox:
      enabled: true
      api_key: ''
      refresh_hours: 6
```

- `cache_ttl_hours`: Age after which cached lookup results are stale.
- Each provider has `enabled`, `api_key`, and `refresh_hours`.
- Bulk feeds are refreshed by `app/threat_intel_worker.py`; matching happens
  locally in `app/threat_intel.py`.
- VirusTotal is separate post-AI verification for eligible public IPs in
  Dangerous cases. It does not change a numerical score.
- Never commit a real API key. `config.yaml` is local and should remain ignored
  by Git. Dashboard responses and logs must use redacted settings.

### Legacy Compatibility Fields

Older databases and some internal functions retain names such as `assets`,
`thresholds`, and historical evaluation tables for migration compatibility.
They are not part of the current evaluated asset-inventory, scoring, firewall,
or scenario-evaluation workflow. Do not describe them as active features merely
because a column or compatibility endpoint still exists.

## Python Module Map

### Runtime and orchestration

| Module | What it does | Typical safe changes |
|---|---|---|
| `app/main.py` | Defines CLI commands, starts required workers, builds case evidence, coordinates ingestion and AI assessment | Add a CLI command or worker; avoid changing required-worker shutdown behavior casually |
| `app/config.py` | Defines defaults, merges YAML, saves settings, maps old key names | Add a documented setting with a conservative default |
| `app/bootstrap.py` | Checks Ubuntu/tools, discovers interfaces, configures Zeek and Community ID | Update installation checks or prompts after testing on the target OS |
| `app/security.py` | Redacts secrets from errors and API output | Add new credential field names when adding providers |

### Sensor ingestion and normalization

| Module | What it does | Typical safe changes |
|---|---|---|
| `app/suricata_reader.py` | Follows EVE JSON with persistent checkpoints | Change retry diagnostics; preserve checkpoint acknowledgement semantics |
| `app/normalizer.py` | Extracts Suricata timestamp, endpoints, ports, protocol, signature, flow ID, and Community ID | Extend broad label rules or retain a new EVE field |
| `app/zeek_ingest.py` | Follows configured Zeek JSON logs with per-file checkpoints | Add a supported log file while preserving checkpoint behavior |
| `app/zeek_normalizer.py` | Converts Zeek rows into common fields and bounded protocol summaries | Add fields for a specific Zeek log type |
| `app/zeek_inventory.py` | Reports Zeek installation, process, paths, permissions, and log status | Improve health checks |
| `app/sensor_fusion.py` | Produces a common finding structure for both sensors | Add a common provenance field |
| `app/correlator.py` | Creates initial Suricata-side case information | Adjust initial case fields with matching database changes |

### Storage and correlation

| Module | What it does | Typical safe changes |
|---|---|---|
| `app/database.py` | Opens SQLite, applies migrations, stores evidence, correlates findings, manages queues, and builds dashboard read models | Add migrations and query helpers; never delete existing columns to “clean up” a live database |
| `sql/schema.sql` | Baseline schema for new databases | Keep synchronized with migrations in `app/database.py` |

Important identifiers:

- `SUR-...`: normalized Suricata event UID.
- `ZEK-...`: normalized Zeek event UID.
- `CASE-...`: centralized investigation case UID.
- Community ID: common flow hash generated by Suricata and Zeek using the same
  version/seed; used for correlation, not as a security verdict.
- Zeek UID: Zeek connection identifier used to connect Zeek protocol logs.

### Threat intelligence and decisions

| Module | What it does | Typical safe changes |
|---|---|---|
| `app/threat_intel.py` | Downloads/normalizes provider feeds and matches IP/domain/URL/hash observables | Add a provider adapter and sanitization tests |
| `app/threat_intel_worker.py` | Refreshes enabled feeds on schedule | Adjust scheduling behavior |
| `app/enrichment.py` | Reports enrichment state and retains limited compatibility helpers | Prefer `threat_intel.py` for new provider work |
| `app/virustotal.py` | Performs post-AI verification of eligible public IPs | Adjust eligibility/status handling without exposing the key |
| `app/decision_engine.py` | Validates qualitative class and maps it to Python-controlled action | Change policy only with regression tests |

### AI request and research workflow

| Module | What it does | Typical safe changes |
|---|---|---|
| `app/ai_client.py` | Builds bounded evidence, constructs prompt, computes hashes, sends request, parses JSON, validates response, and records audit data | Change prompt wording, schema, limits, or request options with audit and parsing tests |
| `app/ai_activity.py` | Tracks preparing/requesting/completed/failed/cancelled request states | Add operator-visible progress fields |
| `app/case_assessment.py` | Rebuilds evidence and reassesses an existing case | Change reassessment evidence policy |
| `app/ai_comparison.py` | Freezes one input, runs model profiles sequentially, records anonymized responses/votes, and executes controlled experiments | Add experimental variants while preserving identical-input proof |
| `app/evaluation.py` | Historical scenario-evaluation compatibility code | Retired from the current experiment methodology; do not use for new work |

## How the Prompt Is Built

The most important professor demonstration is in `app/ai_client.py`:

1. `app/main.py::build_ai_evidence_context` obtains relevant sensor findings,
   bounded Zeek context, recurrence, and threat-intelligence results.
2. `app/ai_client.py` compacts the package. It removes secrets/raw records,
   limits nesting, limits list items, and limits long strings.
3. Python serializes the normalized dictionary into JSON text.
4. The JSON text is embedded in versioned instructions. It is a text prompt,
   not an uploaded file.
5. `ask_ai_model()` sends the prompt, JSON output schema, model name, context,
   output limit, temperature, and seed to `/api/generate`.
6. Python parses and normalizes the response. Invalid, incomplete, or
   low-confidence output is routed conservatively to analyst review.
7. SQLite stores the exact prompt, evidence package, omissions, hashes, token
   counts, response, model profile, and elapsed time.

Prompt SHA-256 proves the exact prompt text stored by Python. Evidence SHA-256
proves the normalized evidence snapshot. It does not prove that a remote model
independently rehashed the request; Ollama's measured `prompt_eval_count` and
the returned response provide additional request-processing evidence.

## Dashboard and Browser Files

| Browser file | Page |
|---|---|
| `static/index.html` + `static/app.js` | Main dashboard and combined event stream |
| `static/investigation.html` + `static/investigation.js` | Case evidence, AI explanation, analyst review, sensor logs |
| `static/compare.html` + `static/compare.js` | Anonymous model comparison and winner selection |
| `static/experiments.html` + `static/experiments.js` | Temperature/seed and missing-evidence experiments |
| `static/admin.html` + `static/admin.js` | AI profiles, threat-intelligence settings, runtime console |
| `static/zeek.html` + `static/zeek.js` | Zeek health, log counts, and telemetry |
| `static/styles.css` | Shared responsive visual design |
| `app/dashboard.py` | FastAPI routes and JSON APIs used by all pages |

HTML defines structure, JavaScript calls `/api/...` endpoints and renders data,
and CSS controls layout. Business logic and security decisions should remain in
Python rather than browser JavaScript.

## CLI Commands to Demonstrate

```bash
# Start required sensors/workers and dashboard
python -m app.main run-all --config config.yaml

# Expose dashboard only on a trusted management interface when required
python -m app.main run-all --config config.yaml --host 192.168.57.134 --port 8000

# Check Zeek installation, process, and logs
python -m app.main zeek-status --config config.yaml

# Run components separately for debugging
python -m app.main ingest --config config.yaml
python -m app.main zeek-ingest --config config.yaml
python -m app.main ai-worker --config config.yaml
python -m app.main threat-intel --config config.yaml
python -m app.main dashboard --config config.yaml --host 127.0.0.1 --port 8000
```

Avoid `0.0.0.0` unless access is restricted by a trusted management network and
host controls. The dashboard does not provide full production authentication.

## Safe Change Checklist

Before changing code or research settings:

1. Create or use a development branch.
2. Copy `config.yaml` before changing deployment values.
3. Never commit real API keys, passwords, or the live SQLite database.
4. Add a migration rather than deleting or renaming a live database column.
5. Document correlation-window, prompt, model, temperature, seed, and context
   changes because they affect experimental interpretation.
6. Run:

```bash
./venv/bin/python -m compileall -q app
./venv/bin/python -m unittest discover -s tests -q
git diff --check
```

7. Verify `/api/tags`, Zeek status, Suricata EVE updates, and one complete case
   before collecting experiment data.

## Two-Minute Professor Walkthrough

1. Open `config.yaml` and identify the Suricata EVE path, Zeek interface, AI
   service URL/model, `num_ctx`, `num_predict`, temperature, and seed.
2. Open `app/main.py` and show the required ingestion and AI workers.
3. Open `app/suricata_reader.py` and `app/zeek_ingest.py` to show checkpointed
   local log reading.
4. Open `app/database.py` to show original evidence storage, stable UIDs, and
   correlation into a case.
5. Open `app/ai_client.py` at prompt construction and `ask_ai_model()` to show
   the normalized JSON evidence, request options, and `/api/generate` call.
6. Open a case's AI audit in the dashboard to show exact prompt, evidence,
   omissions, hashes, token counts, model identity, response, and elapsed time.
7. Explain that Python retains the original logs and final policy control; the
   AI supplies a qualitative, reviewable interpretation.

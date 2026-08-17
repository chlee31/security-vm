# Security VM Code Walkthrough

This guide explains how the Python modules cooperate and where to look when
demonstrating the implementation. The comments in the source describe local
decisions; this document provides the end-to-end map.

## End-to-End Case Flow

1. `app/suricata_reader.py` follows Suricata EVE JSON using an inode and byte
   offset checkpoint. A checkpoint advances only after downstream processing
   acknowledges the event.
2. `app/normalizer.py` converts the EVE record into stable alert fields and
   assigns a broad rule-based behavior label.
3. `app/zeek_ingest.py` follows each required Zeek JSON log with an independent
   checkpoint.
4. `app/zeek_normalizer.py` preserves the Zeek log type, UID, Community ID,
   endpoints, protocol fields, and a bounded protocol-specific summary.
5. `app/database.py` stores original sensor JSON, assigns stable `SUR-`, `ZEK-`,
   and `CASE-` identifiers, and links each source row to a unified detection
   through `sensor_findings`.
6. `app/database.py::find_correlated_detection` tries Community ID, Zeek UID,
   endpoint/time flow, shared observable, and repeated-behavior correlation in
   descending order of strength.
7. `app/main.py::build_ai_evidence_context` selects normalized Suricata/Zeek
   findings, bounded Zeek context, recurrence, and
   pre-AI threat-intelligence results.
8. `app/ai_client.py` filters that evidence, builds one JSON-containing text
   prompt, sends it to an Ollama-compatible endpoint, validates the structured
   response, and produces a complete local audit.
9. `app/decision_engine.py` normalizes the qualitative classification and keeps
   final response control in Python. Materially disputed sensor findings force
   `Analyst Review Required`.
10. `app/virustotal.py` may verify eligible public IPs after a `Dangerous`
    classification. VirusTotal does not numerically change or lower the result.

## What Happens When a Sensor Finding Arrives

For a Suricata alert, `run_ingest` follows this order:

1. Read one `event_type: alert` EVE record after the saved byte offset.
2. Normalize the fields needed for searching, correlation, and display.
3. Insert the normalized fields and complete original JSON into `alerts`.
4. Find or create a unified row in `detections`, which receives a `CASE-` UID.
5. Link the alert to that case through `sensor_findings`.
6. Commit the transaction, then advance the file checkpoint.
7. Leave the case for the AI worker to discover through a database query.

Zeek uses the same evidence model, but follows several rotating JSON logs. Every
supported row is written to `zeek_events`. Notice-like rows can create a case;
connection, DNS, TLS, HTTP, file, SSH, X.509, and weird records can be attached
as supporting context. The Zeek checkpoint advances only after storage and any
required case linking succeed.

The AI worker does not rely on an empty placeholder in `ai_reports`. It queries
for a detection whose ID has no corresponding completed AI report, builds that
case's evidence, sends it, and stores the result. Once the report exists, the
same query naturally stops selecting that case. This database-backed queue also
survives browser and worker restarts.

## Why Suricata and Zeek Status Look Different

The difference is code organization, not sensor importance. Both sensors are
required by `run-all` and both feed the same case pipeline.

- Suricata is managed as a normal system service. `app/main.py` only needs a
  short `systemctl is-active/start suricata` prerequisite check. Reading and
  interpreting its evidence are already separated into
  `app/suricata_reader.py` and `app/normalizer.py`.
- ZeekControl manages more application-owned state. Security VM must locate
  `zeek`, `zeekctl`, and `zkg`, inspect ZeekControl process state, report package
  configuration, and test access to several log files. That larger operational
  inventory belongs in `app/zeek_inventory.py` instead of making `main.py` even
  larger.

In short, the inline Suricata code is only a service-health check. It is not the
Suricata inventory, parser, or evidence store. Zeek has a dedicated inventory
module because its runtime checks are materially more complex.

## SQLite Evidence Model

The central relationship is:

```text
alerts (Suricata) ----\
                       > sensor_findings ---> detections (CASE)
zeek_events ----------/                           |
                                                   +--> ai_reports
                                                   +--> ai_assessments
                                                   +--> ai_run_audits
                                                   +--> reviews / responses

threat_intel_sources / indicators / lookups / usage
                         |
                         +-------------------------> case evidence package
```

The tables deliberately separate evidence from interpretation:

| Table | What it stores | Why it exists |
|---|---|---|
| `alerts` | Searchable Suricata fields plus original `raw_json` | Fast correlation and display without losing the authoritative sensor record |
| `zeek_events` | Log type, UID, Community ID, endpoints, details, and original JSON | One common representation for Zeek's protocol-specific logs |
| `detections` | The unified investigation case and correlation summary | Gives related findings one stable `CASE-` identity |
| `sensor_findings` | Links each Suricata or Zeek source row to a case | Supports many findings per case without copying or flattening their source evidence |
| `ai_reports` | The current normalized explanation used by the case page | Makes the latest readable result quick to retrieve |
| `ai_assessments` | Historical initial, reassessment, and comparison outputs | Preserves model history instead of overwriting research evidence |
| `ai_run_audits` | Exact prompt, evidence package, hashes, options, omissions, response, and timing | Proves what Python sent and what the model returned |
| threat-intelligence tables | Provider state, cached indicators, lookups, and case usage | Separates locally collected reputation evidence from model interpretation |
| checkpoint tables | File identity, byte offset, and Zeek record progress | Lets ingestion resume without rereading an entire log after restart |
| `reviews` and `responses` | Analyst feedback and Python-controlled action | Keeps human and application decisions separate from AI text |

Normalized columns answer routine questions efficiently, such as which IP,
port, protocol, sensor, or timestamp was involved. Original JSON is retained so
an analyst can verify extraction and inspect fields that were not promoted into
columns. Stable `SUR-`, `ZEK-`, and `CASE-` identifiers are used in the UI and
audit exports, while SQLite integer keys maintain reliable internal joins.

Schema upgrades use forward-only migrations. New columns and indexes are added
without deleting existing rows, which protects evidence collected by earlier
versions of the prototype.

## Short Presentation Notes

> Suricata writes many kinds of records to EVE JSON, but the application only
> sends records whose `event_type` is `alert` into the Suricata case pipeline.
> `app/normalizer.py` extracts the timestamp, source and destination addresses,
> ports, protocol, signature, severity, Flow ID, and Community ID into a stable
> structure. The complete original event is also retained as `raw_json` for
> audit and verification.
>
> Python then compares the Suricata signature and category with a small,
> documented regular-expression map. Explicit language can label an event as
> `port_scan`, `dns_tunneling`, `beaconing`, or `brute_force`; anything that
> does not match remains `unknown`. This is a grouping heuristic, not the final
> security classification and not a trained machine-learning model.
>
> The normalized event can then be stored, correlated with Zeek evidence, and
> included in a bounded AI evidence package. The AI receives selected text
> evidence rather than the original log file, while SQLite retains the original
> sensor record so an analyst can verify where each field came from.

## How Python Builds the AI Prompt

The central implementation is
`app/ai_client.py::_build_prompt_components`.

### 1. Build the event package

Python creates a dictionary containing:

- event and case identifiers;
- source and destination IP addresses and ports;
- protocol, signature, first seen, and last seen;
- sensor state and correlation method;
- encrypted-traffic visibility limitations; and
- selected sensor, Zeek, recurrence, and threat-intelligence evidence.

The model does not read the SQLite database or sensor log files. Python reads
those sources locally and places selected normalized values into this package.

### 2. Apply evidence controls

`_compact_ai_evidence` recursively enforces:

- no credentials, raw sensor records, or retired score fields;
- maximum nesting depth of eight;
- maximum 25 items in any list; and
- maximum 2,000 characters in an individual string.

Every omission is written to the audit manifest. Raw sensor JSON remains
available locally on the investigation page.

### 3. Serialize the package

Python serializes the dictionary with `json.dumps`. That JSON text is embedded
between the fixed instructions and the response-schema reminder:

```text
[versioned instructions]

[normalized JSON evidence package]

[exact structured-output schema reminder]
```

This is one text prompt in one HTTP request. Security VM does not upload a JSON
file, database, PCAP, or raw sensor file to the model.

### 4. Require structured output

`AI_RESPONSE_SCHEMA` defines the accepted qualitative response:

- classification and confidence;
- reason and case summary;
- who, what, when, where, why, and how;
- two to five next investigation steps;
- a separate interpretation for every threat-intelligence provider;
- an acknowledgement of evidence reviewed; and
- a recommended action.

The schema is supplied in Ollama's `format` request field and repeated after the
evidence. Python still validates and normalizes the result because language
models can return imperfect output.

## Context Length and Token Budget

`app/ai_client.py::ask_ai_model` reads these settings:

```yaml
ai_model:
  num_ctx: 8192
  num_predict: 1024
  temperature: 0.1
```

The configured window is shared by input and output:

```text
estimated input budget = num_ctx - num_predict
estimated input budget = 8192 - 1024
estimated input budget = 7168 tokens
```

Before sending, Python estimates prompt tokens with:

```python
estimated_prompt_tokens = (len(prompt) + 3) // 4
```

This four-characters-per-token calculation is only a planning estimate because
tokenization differs by model. When Ollama returns `prompt_eval_count`, that
value is the measured number of input tokens actually processed.

Security VM sends `num_ctx` in each API request. It therefore controls the
request even if the remote Ollama application's default context slider is
different. Tailscale only transports the HTTP connection and does not alter the
prompt or token settings.

## Exact Ollama-Compatible Request

`ask_ai_model` sends:

```python
requests.post(
    f"{host}/api/generate",
    json={
        "model": model,
        "prompt": prompt,
        "stream": False,
        "format": AI_RESPONSE_SCHEMA,
        "options": {
            "num_predict": configured_output_limit,
            "num_ctx": configured_context_window,
            "temperature": configured_temperature,
        },
    },
    timeout=configured_timeout,
)
```

The endpoint can be local, LAN-accessible, or reachable through Tailscale. The
transport location does not change evidence selection or context calculation.

## Proof Stored for Every AI Request

`build_prompt_audit` prepares proof before transmission, and
`database.py::upsert_ai_run_audit` writes it to `ai_run_audits`.

The audit contains:

- exact prompt and normalized evidence package;
- prompt, package, and response SHA-256 values;
- character and UTF-8 byte counts;
- model profile, model run, case, and prompt-version identifiers;
- source map back to SQLite row IDs and sensor UIDs;
- omission and truncation manifest;
- configured context, output, temperature, and timeout;
- estimated prompt tokens;
- Ollama's measured `prompt_eval_count` and `eval_count`;
- raw model response and parse status.

The model's `evidence_review` response states what it claims to have considered.
The Python-captured prompt, hashes, and source map are the authoritative proof
of delivery.

## Response Safety

`parse_model_response` first tries strict JSON, then handles Markdown fences or
a short prefix. A limited scalar recovery path can retain useful text from a
truncated response.

`normalize_report`:

- converts supported legacy formats;
- removes any returned scoring field;
- validates qualitative confidence and actions;
- supplies explicit fallback text for missing sections; and
- limits arrays to the schema's expected sizes.

Malformed or partial responses become `Analyst Review Required` with Low
confidence. Model failure cannot silently classify a case as safe.

## Module Responsibilities

| Module | Responsibility |
|---|---|
| `app/main.py` | CLI commands, required-worker orchestration, sensor service checks, and initial case coordination |
| `app/config.py` | YAML defaults, merge, legacy normalization, persistence |
| `app/bootstrap.py` | Host prerequisites, interfaces, routing, Zeek setup |
| `app/suricata_reader.py` | Reliable checkpointed EVE JSON following |
| `app/normalizer.py` | Suricata normalization and broad behavior labels |
| `app/zeek_ingest.py` | Required multi-log Zeek ingestion |
| `app/zeek_normalizer.py` | Zeek normalization and protocol evidence summaries |
| `app/zeek_inventory.py` | Rich Zeek binary, ZeekControl, package, process, and log-access status |
| `app/sensor_fusion.py` | Common Suricata/Zeek finding representation |
| `app/correlator.py` | Initial Suricata case record |
| `app/database.py` | SQLite schema, migrations, evidence, correlation, read models |
| `app/threat_intel.py` | Provider configuration, feed refresh, cached IOC matching |
| `app/threat_intel_worker.py` | Scheduled bulk-feed refresh |
| `app/enrichment.py` | Enrichment status and legacy OTX helpers |
| `app/virustotal.py` | Separate post-AI Dangerous-case verification |
| `app/ai_client.py` | Prompt, context, API request, parsing, and audit |
| `app/case_assessment.py` | Existing-case reassessment |
| `app/ai_comparison.py` | Sequential multi-model comparison |
| `app/decision_engine.py` | Python-controlled qualitative action policy |
| `app/dashboard.py` | FastAPI pages and management/read APIs |
| `app/security.py` | Credential redaction |

## Short Demonstration Explanation

> Python receives Suricata and Zeek JSON locally and stores the original records
> in SQLite. It correlates related rows into a case and selects a bounded set of
> normalized fields, Zeek protocol context, and threat-intelligence results.
> Python serializes that evidence into JSON text inside one versioned prompt. It
> sends the prompt to the configured Ollama-compatible `/api/generate` endpoint
> with an explicit 8,192-token context and JSON response schema. The model never
> receives credentials, raw files, or direct database access. Python stores the
> exact prompt, source lineage, omissions, hashes, token measurements, and
> response, then retains final control over the qualitative action.

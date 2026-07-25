# AI Evidence Audit and Data Lineage

Security VM records proof of every new AI request in SQLite. The authoritative record is captured by Python before and after the HTTP request; it does not depend on the model repeating the prompt correctly.

## Context and Input Policy

Security VM does not send files directly to an Ollama-compatible model and does not rely on a 4 KB file limit. Python reads locally stored Suricata, Zeek, correlation, registered-IP, and threat-intelligence records; selects the records relevant to the case; normalizes them into structured JSON text; and embeds that bounded package in the model prompt. Raw packet captures, complete database files, API keys, and passwords are not sent.

The operative limit is the configured token context. The default `num_ctx` is 8,192 tokens and includes both input and generated output. The default `num_predict` reserves up to 1,024 tokens for the response, leaving an estimated input budget of approximately 7,168 tokens. These deployment settings remain in effect even when a model advertises a much larger maximum context, such as approximately 131,072 tokens for Llama 3.1/3.2 or 1,048,576 tokens in the currently installed Nemotron metadata.

Character and byte counts are retained for transport auditing, but they are not token counts. Python's pre-request token value is only an estimate. When returned by the model server, `prompt_eval_count` is the authoritative measurement of processed input tokens and `eval_count` is the generated response-token count.

## Audit Record

The `ai_run_audits` table stores one row per initial assessment, reassessment, backfill, or comparison-model request:

- case/detection ID, model profile UID, model run UID, provider, model, and prompt version;
- exact prompt text sent to `/api/generate`;
- exact normalized evidence package embedded in that prompt;
- SHA-256, character count, and UTF-8 byte count for the prompt, evidence, and response;
- safe request settings such as context size, output limit, temperature, timeout, response-schema hash, and streaming state;
- an estimated prompt-token/context-budget check plus the model server's actual `prompt_eval_count` when it returns one;
- a source map linking evidence sections to SQLite tables, row IDs, event UIDs, Zeek UIDs, and Zeek log types;
- an omission manifest for every raw/sensitive field, over-depth value, list item, or long string excluded by Python;
- complete model response, parse state, parse error, status, and timestamps.

API keys and passwords are excluded before prompt construction and are never placed in the audit row. Raw Suricata and Zeek records stay local and are not sent to the model.

## Sensor Proof

The investigation page displays each correlated `sensor_findings` row with:

- originating sensor and SQLite source table (`alerts` or `zeek_events`);
- source row ID and stable event UID;
- timestamp, source/destination IP, source/destination port, and protocol;
- raw-record SHA-256 and byte count;
- field-level lineage showing where each normalized value came from;
- expandable original sensor JSON stored in SQLite.

The case also displays the correlation method. A shared Community ID is shown when available. Otherwise, the page identifies the configured flow, endpoint, time-window, or same-sensor method used by Python. Community ID and Zeek UID help correlation but do not replace the original records.

## Model Evidence Acknowledgement

New responses include an `evidence_review` object containing:

- `received_sections`;
- `evidence_used`;
- `missing_or_ambiguous`;
- `review_method`.

This tells an analyst what the model claims it reviewed. It is explanatory evidence, not proof of delivery. The exact Python-captured prompt, normalized package, hashes, and HTTP settings are the delivery proof.

## Zeek Data Path

1. `app/zeek_ingest.py` reads configured Zeek JSON logs.
2. `app/database.py` stores original records in `zeek_events` and creates `sensor_findings` for detection-producing events.
3. `app/database.py::zeek_context_for_detection` selects bounded protocol context for a case.
4. `app/main.py::build_ai_evidence_context` identifies available and included Zeek rows, preserves log type/UID/endpoint provenance, and adds cached threat-intelligence matches.
5. `app/ai_client.py::_build_prompt_components` embeds that normalized context in the audited evidence package.
6. `app/ai_client.py::ask_ai_model` sends the exact prompt and returns the response plus audit metadata.
7. `app/database.py::upsert_ai_run_audit` stores the complete local proof.

The normal AI package includes at most eight selected Zeek context rows. The audit record states how many rows were available, how many were included, and the selection policy. Additional generic list and string limits are recorded in the omission manifest rather than applied silently.

## Reviewing an Audit

Open a case from the dashboard and use **AI Request and Data Lineage**. Expand:

1. **Exact prompt sent to the model**
2. **Exact normalized evidence package**
3. **Source map and correlation lineage**
4. **Python omission and truncation manifest**
5. **Request settings and structured-output contract**

Historical rows created before this migration retain their existing AI reports but cannot reconstruct an exact past request. Their case page explicitly labels the full request audit as unavailable.

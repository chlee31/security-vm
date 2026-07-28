# Security VM Current Development Update

## Scope

This document summarizes the complete local development update made after the
current GitHub `dev` baseline. It covers the runtime, AI, case-review,
comparison, dashboard, database, export, and test changes.

## Executive Summary

The update strengthens Security VM in five main areas:

1. Sensor ingestion is separated from AI processing so model latency does not
   block Suricata or Zeek evidence collection.
2. AI prompts are compacted, auditable, and validated against supplied
   evidence.
3. Three-model comparisons use consistent input and support a complete analyst
   review workflow.
4. Cases group repeated findings while retaining every original sensor record.
5. Administrative runtime visibility, exports, provenance, and regression
   testing are expanded.

## Sensor and AI Processing

AI assessment has been moved out of the live sensor-ingestion path:

1. Suricata and Zeek records are normalized, correlated, and stored in SQLite.
2. Sensor checkpoints advance after the evidence is stored.
3. A separate AI worker finds cases without an AI report.
4. The worker constructs the evidence package, sends the request, validates
   the response, and stores the report.

This prevents slow or unavailable models from pausing sensor ingestion.
Runtime heartbeat data now shows whether major workers are active or stale.

Suricata checkpoint handling continues to account for file rotation,
truncation, and source fingerprints. Checkpoints no longer wait for model
responses.

## Prompt Construction and Grounding

Python now compacts repeated sensor findings for model input. Findings are
grouped using sensor, event type, addresses, destination port, and protocol.
The model receives occurrence counts, first and last timestamps, and
representative examples. Original Suricata and Zeek records remain unchanged
in SQLite and remain available on the case page.

The prompt now states that:

- Safe and Dangerous conclusions require concrete evidence;
- encrypted, unfamiliar, or repeated traffic is not automatically dangerous;
- a threat-intelligence no-match is not proof that traffic is safe;
- malicious provider matches must exist in the supplied provider evidence;
- concrete case fields must replace generic placeholders; and
- grouped records represent repeated observations.

Python validates model output against the evidence package. It corrects
unsupported threat-intelligence claims and can force unsupported Safe or
Dangerous conclusions to Analyst Review Required with reduced confidence.
Python therefore retains final control over the stored result.

## Auditable and Consistent Model Input

When an initial audited AI request exists, comparison runs reuse its exact
stored prompt and normalized evidence snapshot. If an older case has no
snapshot, Python creates one shared comparison snapshot.

Each request records:

- prompt and evidence SHA-256 hashes;
- response hash;
- model and profile identifiers;
- request settings;
- omission and truncation information; and
- measured request time.

Comparison requests use temperature `0` and seed `42` to reduce avoidable
variation. Hashes allow the dashboard and exports to prove whether candidates
received identical input.

## Three-Model Comparison

The three model requests run sequentially so multiple local models are not
loaded simultaneously. A comparison lock prevents overlapping runs.

The application records progress after every candidate attempt and reports:

- attempted and successful request counts;
- running, complete, partial, or failed status;
- sanitized failures;
- candidate provenance; and
- elapsed request time.

Candidates are presented as Response A, B, and C before review. Model identity
is revealed after the analyst selects a winner.

Analysts can:

- select A, B, or C;
- reject all candidates;
- record a tie;
- add review notes;
- reopen a completed review; and
- inspect review history.

The queue can be filtered by pending, reviewed, rejected, tie, and failed
states.

## Selected Response Promotion

After selecting a winner, the analyst can use **Use Selected Response on
Case**. The case page then displays the selected candidate's:

- summary;
- explanation of why the activity may matter;
- recommended next steps;
- confidence; and
- raw response.

The promotion records the case, comparison, candidate, report, profile, model
run, and timestamp. It does not overwrite raw sensor evidence,
Python-derived facts, threat-intelligence records, analyst notes, the original
AI report, or the stored final case decision.

## Comparison Statistics, Timing, and Export

The comparison workspace reports total runs, unique cases, reviewed cases,
rejections, ties, reopened reviews, partial runs, and failed runs.

CSV and JSON exports include case and comparison identifiers, review state,
notes, selected candidate, revealed model identity, candidate status,
classification, confidence, hashes, review history, and timing.

Timing fields include:

- Response A, B, and C milliseconds and seconds;
- selected-response time;
- total and average successful model time;
- comparison wall-clock time; and
- creation, completion, and review timestamps.

## Dashboard and Case Interface

The product title is now **Security VM**, and the primary investigation area
is labelled **Cases**.

The main dashboard is simplified around sensor findings, case outcomes, and
latest correlated alerts. Repeated findings display as a primary record with a
`+N` count.

Case pages provide:

- grouped and all-event sensor views;
- separate scrollable Suricata and Zeek lists;
- event UIDs and timestamps;
- addresses, ports, and protocols;
- Community ID and correlation context;
- expandable raw source records;
- source labels distinguishing Python facts from AI interpretation; and
- the selected comparison explanation when one has been promoted.

Cases awaiting AI processing no longer display fabricated recommendations or
an unknown model. AI fields remain empty until a report exists.

## Administrative Runtime Console and Access

The Admin page now contains a runtime console showing:

- component heartbeats;
- active and recent AI requests;
- prompt-building, sending, receiving, parsing, and storage phases;
- sanitized application events; and
- request timing and status.

Administrative pages and `/api/admin/*` endpoints use HTTP Basic
authentication configured by:

- `SECURITY_VM_ADMIN_USER`; and
- `SECURITY_VM_ADMIN_PASSWORD`.

The password is not stored in SQLite or returned by dashboard APIs. This
protects the administrative area but is not a complete authentication system
for every dashboard page.

## SQLite and API Changes

Additive migrations preserve existing SQLite data while adding:

- AI request lifecycle activity;
- runtime worker heartbeats;
- comparison progress;
- comparison review history;
- selected-response promotion records;
- initial audited request snapshots;
- candidate failure and timing provenance; and
- exportable review metadata.

APIs were added or expanded for the runtime console, comparison details,
review reopening, CSV and JSON export, winner selection, selected-response
promotion, and grouped or raw case evidence.

## Validation

Regression tests cover:

- checkpointing before AI processing;
- pending-case AI worker behavior;
- AI request activity;
- repeated-finding compaction;
- exact prompt-snapshot reuse;
- comparison locking;
- failed-candidate provenance;
- unsupported threat-intelligence correction;
- unsupported verdict downgrade;
- empty AI state;
- review reopening;
- rejection statistics;
- winner promotion; and
- timing export.

Latest validation:

```text
87 tests passed
```

Python compilation and Git whitespace validation also passed. JavaScript
syntax validation with Node.js was unavailable because Node.js is not
installed in the development environment.

## Report-Ready Summary

The revised Security VM separates network-sensor ingestion from model
assessment so Suricata and Zeek evidence can be stored and checkpointed
without waiting for a language model. Python constructs a normalized and
auditable evidence package, compacts repeated findings for model input, and
validates returned claims against supplied sensor and threat-intelligence
evidence. A sequential three-model workflow allows analysts to review
anonymized responses, select or reject candidates, reopen decisions, and
export response-quality and timing data. A selected response may become the
visible case explanation while original sensor records, Python-derived facts,
analyst history, and the initial model report remain preserved for provenance.

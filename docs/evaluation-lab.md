# Evaluation Lab

The Evaluation Lab is a research workspace built alongside the operational Security VM case workflow. It stores analyst-defined ground truth and references existing cases without changing their official correlation, score, classification, AI report, or analyst review.

## Routes

| Page | Purpose |
|---|---|
| `/evaluation` | Evaluation overview and record counts |
| `/evaluation/scenarios` | Create scenarios and link existing Security VM cases |
| `/evaluation/correlation` | Label expected and actual event membership |
| `/evaluation/scoring` | Browse frozen case inputs for later sensitivity runs |
| `/evaluation/models` | Browse existing three-model comparison runs |

The corresponding APIs use the `/api/evaluation` prefix.

## Phase 1 Workflow

1. Open `/evaluation/scenarios`.
2. Create the scenario before running the controlled test when practical.
3. Record the authorization state, whether the attack succeeded, time window, endpoints, expected sensors, and expected case count from external lab knowledge.
4. Run the controlled traffic.
5. Link the resulting Security VM case or cases to the scenario.
6. Open `/evaluation/correlation`.
7. Assign the expected case for each candidate event. Security VM derives the
   actual case from the operational database and calculates the result:
   - expected and actual case match: true positive;
   - expected case is present but no actual case exists: false negative;
   - no expected case is present but an actual case exists: false positive;
   - expected and actual cases differ: one false negative and one false positive;
   - neither case is present: true negative.
8. Export one scenario or the complete evaluation dataset as JSON or CSV.

Security VM does not infer ground truth from its own score or AI output.

## Correlation Ground Truth

The expected and actual case assignments are the source of truth. The analyst
enters `expected_case_uid`; the API derives `actual_case_uid` from the
`sensor_findings` and `detections` tables. The browser cannot override the
stored actual assignment.

An actual case must exist and must be linked to the scenario before the event
can be labelled. An expected case can identify a linked operational case or a
manually declared expected case that was never created by the system. This
supports scenarios that should produce more than one case and exposes events
attached to the wrong case.

The backend calculates:

```text
precision = TP / (TP + FP)
recall = TP / (TP + FN)
F1 = 2 * precision * recall / (precision + recall)
```

Undefined ratios are exported as `null` and displayed as `N/A`; they are not
reported as zero. The current calculation version is
`correlation-metrics-v1`.

Metrics are available from:

```text
/api/evaluation/scenarios/{scenario_uid}/correlation-metrics
```

## Candidate Event Boundary

Metrics are calculated only from an explicit candidate set. A candidate event
must occur inside the scenario time window and match at least one of:

- a registered scenario source or destination IP;
- an event belonging to a case linked to the scenario;
- a Community ID shared with an endpoint or linked-case event;
- a Zeek UID shared with an endpoint or linked-case event;
- an event UID manually designated as a distractor.

The candidate definition is stored in `candidate_scope_json` with the scenario.
The candidate API is:

```text
/api/evaluation/scenarios/{scenario_uid}/candidates
```

This boundary prevents arbitrary unrelated events from being added as true
negatives after an experiment. Legacy or imported labels that no longer fit the
stored boundary are reported as out of scope and do not affect TP, FP, FN, or
TN.

## SQLite Tables

| Table | Contents |
|---|---|
| `evaluation_scenarios` | Controlled scenario definition and manual ground truth |
| `evaluation_case_links` | References from a scenario to existing case UIDs |
| `evaluation_event_labels` | Expected and actual case assignments for candidate events |
| `evaluation_scoring_runs` | Evaluation-only scoring experiment results |
| `evaluation_model_reviews` | Manual rubric results for stored model responses |

Scenario deletion removes only records in the evaluation tables. It does not delete or modify operational cases.

## Exports

Download all evaluation records:

```text
/api/evaluation/export?format=json
/api/evaluation/export?format=csv
```

Download one scenario:

```text
/api/evaluation/export?format=json&scenario_uid=COR-001
/api/evaluation/export?format=csv&scenario_uid=COR-001
```

Exports include the backend correlation confusion matrix and metric values.
They do not include `config.yaml`, provider credentials, AI endpoint
credentials, or threat-intelligence API keys. CSV fields beginning with
spreadsheet formula characters are neutralized before export.

## Reproducibility Metadata

The later correlation-run phase must store a separate run record for each
configuration tested. One scenario may therefore have narrow, current, and
wide runs without changing its ground truth. Each run must preserve:

- Git commit SHA;
- correlation policy version;
- cross-sensor, repeated-behaviour, and Zeek-context windows;
- Community ID availability;
- Suricata version and ruleset date or identifier;
- Zeek version;
- test-run UID;
- evaluation metric version.

These fields belong in a future `evaluation_correlation_runs` table rather than
the base scenario table.

## Current Scope

Phase 1.1 provides the database foundation, scenario CRUD, case linking,
expected-versus-actual event assignments, backend precision/recall/F1
calculation, bounded candidate events, exports, and read-only access to frozen
cases and existing model runs.

The following experiment engines remain subsequent phases:

- deterministic score ablation, multiplier, threshold, and AI-adjustment sweeps;
- blinded manual LLM rubrics and aggregate model scorecards;
- stored narrow/current/wide correlation-configuration comparisons and
  complete case-construction metrics with reproducibility metadata;
- model-review exports containing frozen evidence and prompt hashes, candidate
  responses, latency, parse status, identity reveal data, and rubric values;
- scoring-run exports containing the complete frozen baseline score breakdown.

Those phases must continue to write only to evaluation tables.

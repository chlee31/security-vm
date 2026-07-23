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
7. Label each candidate event using analyst ground truth:
   - expected and correctly attached;
   - expected but missing;
   - unexpected and incorrectly attached;
   - correctly excluded.
8. Export one scenario or the complete evaluation dataset as JSON or CSV.

Security VM does not infer ground truth from its own score or AI output.

## SQLite Tables

| Table | Contents |
|---|---|
| `evaluation_scenarios` | Controlled scenario definition and manual ground truth |
| `evaluation_case_links` | References from a scenario to existing case UIDs |
| `evaluation_event_labels` | Manual event-membership decisions |
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

Exports do not include `config.yaml`, provider credentials, AI endpoint credentials, or threat-intelligence API keys.

## Current Scope

Phase 1 provides the database foundation, scenario CRUD, case linking, event labels, basic precision/recall/F1 calculation from those labels, exports, and read-only access to frozen cases and existing model runs.

The following experiment engines remain subsequent phases:

- deterministic score ablation, multiplier, threshold, and AI-adjustment sweeps;
- blinded manual LLM rubrics and aggregate model scorecards;
- stored narrow/current/wide correlation-configuration comparisons and complete case-construction metrics.

Those phases must continue to write only to evaluation tables.

# Controlled LLM Experiments

Security VM provides three related evaluation workflows. They are research
features and never replace sensor evidence, the official case assessment, or an
analyst decision.

## Baseline Comparison

Open `/compare`, select a stored case, and select one or more active AI
profiles. The selected order is stored with the run. The API returns a
comparison UID immediately, and the persistent experiment worker calls each
model sequentially.

The frozen control uses:

```yaml
temperature: 0.0
seed: 42
num_ctx: 8192
num_predict: 1024
stream: false
```

Before queueing, Python reads the Ollama-compatible `/api/tags` endpoint and
stores the full model digest, size, and available model details. Every
successful candidate receives the same prompt text, normalized evidence,
prompt version, and generation controls. Responses are labeled `R01`, `R02`,
and onward. Identity is hidden until review.

The comparison CSV endpoint is:

```text
/api/ai-comparisons/export?format=csv
```

It emits one row per candidate rather than one model-specific group of columns
per run. This keeps the dataset rectangular when comparisons contain different
numbers of models.

## Temperature And Seed Stability

Open `/experiments/stability` and choose a completed or partially completed
baseline. Each successful control candidate is rerun for every submitted
temperature/seed pair. The original prompt and evidence bytes are reused, so
their SHA-256 values must equal the control values. A current model digest that
does not match the control blocks the experiment.

The page includes the control response, experimental response, equality checks,
request settings, timing, manual evaluation, and CSV/JSON export.

## Missing-Evidence Robustness

Open `/experiments/missing-evidence` and choose a reviewed baseline with a
successful winner. Select one or more evidence categories to remove. Python
deep-copies the frozen package, applies the mask consistently, records the mask,
and inserts explicit `not_provided_for_experiment` markers. Only the winning
model is rerun, using the control model digest and generation settings.

The baseline winner remains immutable. Variant prompt and evidence hashes are
expected to differ because the removal is intentional. The page shows the
control and variant responses together and supports manual grounding,
completeness, uncertainty, usefulness, and claim-count review fields.

## Durable Worker

`run-all` starts `experiment-worker` as a required component:

```bash
python -m app.main run-all --config config.yaml
```

For a standalone dashboard session, run the worker in another terminal:

```bash
python -m app.main experiment-worker --config config.yaml
```

Queue state and progress live in SQLite. Claims are transactional, individual
failures do not delete successful results, and stale claims can be recovered
after a stopped worker.

## Experiment Export

```text
/api/ai-experiments/export?format=csv&experiment_type=sampling_stability
/api/ai-experiments/export?format=csv&experiment_type=missing_evidence
```

Each row links the experiment to its parent comparison and baseline candidate.
It includes model build identity, masks or temperature/seed settings, parent
and variant hashes, baseline and variant response fields, request controls,
model token/timing metrics, parse status, errors, and manual review values.

API keys and credentials are never included in prompts, audits, dashboard
responses, or exports. Experiment requests cannot perform containment actions.

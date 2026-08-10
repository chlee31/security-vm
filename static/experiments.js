// Controlled-experiment page for temperature/seed and missing-evidence tests.
// Jobs are queued through FastAPI and run durably in the background; this file
// only configures experiments and displays their saved results.
const isMissingEvidence = window.location.pathname.includes("missing-evidence");
const type = isMissingEvidence ? "missing_evidence" : "sampling_stability";
const els = {
  updated: document.querySelector("#experiment-updated"),
  refresh: document.querySelector("#experiment-refresh"),
  title: document.querySelector("#experiment-title"),
  number: document.querySelector("#experiment-number"),
  form: document.querySelector("#experiment-form"),
  baseline: document.querySelector("#experiment-baseline"),
  controls: document.querySelector("#experiment-controls"),
  status: document.querySelector("#experiment-status"),
  runs: document.querySelector("#experiment-runs"),
  detail: document.querySelector("#experiment-detail"),
  detailTitle: document.querySelector("#experiment-detail-title"),
  csv: document.querySelector("#experiment-csv"),
  json: document.querySelector("#experiment-json")
};
let runs = [];
let selectedUid = null;

function escapeHtml(value) {
  return String(value ?? "").replaceAll("&", "&amp;").replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#039;");
}

async function jsonRequest(path, options = {}) {
  const response = await fetch(path, {
    cache: "no-store",
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.detail || `${path} returned ${response.status}`);
  return data;
}

function configurePage() {
  els.number.textContent = isMissingEvidence ? "Experiment 3" : "Experiment 2";
  els.title.textContent = isMissingEvidence
    ? "Missing-Evidence Honesty and Robustness"
    : "Temperature and Seed Stability";
  els.csv.href = `/api/ai-experiments/export?format=csv&experiment_type=${type}`;
  els.json.href = `/api/ai-experiments/export?format=json&experiment_type=${type}`;
  if (isMissingEvidence) {
    const masks = [
      ["zeek_context", "Zeek context"],
      ["threat_intelligence", "Threat intelligence"],
      ["source_ip", "Source IP"],
      ["destination_ip", "Destination IP"],
      ["ports", "Source and destination ports"],
      ["protocol", "Protocol"],
      ["correlation", "Correlation context"],
      ["suricata_details", "Suricata details"]
    ];
    els.controls.innerHTML = `
      <label class="field"><span>Variant label</span><input id="variant-label" value="Evidence removal trial"></label>
      <fieldset><legend>Evidence to remove</legend><div class="comparison-vote-options">
        ${masks.map(([value, label]) => `<label><input type="checkbox" name="mask" value="${value}"><span>${label}</span></label>`).join("")}
      </div></fieldset>`;
  } else {
    els.controls.innerHTML = `
      <p>Control: temperature 0.0, seed 42. The stored baseline is not rerun.</p>
      <div id="stability-rows">
        ${[
          ["Low variation", 0.2, 42],
          ["Higher variation, same seed", 0.7, 42],
          ["Higher variation, seed 7", 0.7, 7],
          ["Higher variation, seed 99", 0.7, 99]
        ].map(([label, temperature, seed]) => `
          <div class="form-grid experiment-setting">
            <label class="field"><span>Label</span><input name="setting-label" value="${label}"></label>
            <label class="field"><span>Temperature</span><input name="temperature" type="number" min="0" step="0.1" value="${temperature}"></label>
            <label class="field"><span>Seed</span><input name="seed" type="number" step="1" value="${seed}"></label>
          </div>`).join("")}
      </div>`;
  }
}

async function loadBaselines() {
  const comparisons = await jsonRequest("/api/ai-comparisons?limit=200");
  const eligible = comparisons.filter((run) =>
    ["complete", "partial"].includes(run.status)
    && (/^R\d+$/.test(run.selection || "") || /^[A-Z]$/.test(run.selection || ""))
  );
  els.baseline.innerHTML = eligible.length
    ? eligible.map((run) =>
      `<option value="${escapeHtml(run.comparison_uid)}">${escapeHtml(run.case_uid)} · selected ${escapeHtml(run.selection)} · ${escapeHtml(run.comparison_uid)}</option>`
    ).join("")
    : `<option value="">No analyst-selected comparison responses available</option>`;
  els.baseline.disabled = eligible.length === 0;
  els.form.querySelector("button[type=submit]").disabled = eligible.length === 0;
}

function renderRuns() {
  els.runs.innerHTML = runs.map((run) => `
    <button class="comparison-run-button ${selectedUid === run.experiment_uid ? "selected" : ""}" data-experiment="${escapeHtml(run.experiment_uid)}" type="button">
      <span><strong>${escapeHtml(run.case_uid)} · ${escapeHtml(run.experiment_uid)}</strong>
      <small>${run.completed_task_count}/${run.total_task_count} complete · ${run.failed_task_count} failed</small></span>
      <span class="status-pill">${escapeHtml(run.status)}</span>
    </button>`).join("") || `<div class="empty">No ${isMissingEvidence ? "missing-evidence" : "stability"} experiments yet.</div>`;
}

async function selectRun(uid) {
  selectedUid = uid;
  renderRuns();
  const run = await jsonRequest(`/api/ai-experiments/${encodeURIComponent(uid)}`);
  els.detailTitle.textContent = `${run.case_uid} · ${run.experiment_uid}`;
  const groups = new Map();
  (run.results || []).forEach((result) => {
    const key = result.variant_label || "Unlabelled variation";
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(result);
  });
  els.detail.innerHTML = [...groups.entries()].map(([variant, results], groupIndex) => {
    const first = results[0] || {};
    const complete = results.filter((result) => result.status === "complete").length;
    const failed = results.filter((result) => result.status === "failed").length;
    return `
    <details class="experiment-variation-group" ${groupIndex === 0 ? "open" : ""}>
      <summary class="experiment-variation-head">
        <span>
          <strong>Variation ${groupIndex + 1}: ${escapeHtml(variant)}</strong>
          <small>Temperature ${first.temperature} · seed ${first.seed}</small>
        </span>
        <span class="experiment-variation-progress">${complete}/${results.length} complete${failed ? ` · ${failed} failed` : ""}</span>
      </summary>
      <div class="experiment-variation-results">
        ${results.map((result) => `
    <article class="workbook-row experiment-result-card">
      <div class="row tight"><strong>${escapeHtml(result.anonymous_label)} · ${escapeHtml(result.variant_label)}</strong><span>${escapeHtml(result.status)}</span></div>
      <p>${result.elapsed_ms || 0}ms</p>
      <p>Prompt matches control: ${result.prompt_sha256 === result.parent_prompt_sha256 ? "Yes" : "No"} · Evidence matches control: ${result.evidence_sha256 === result.parent_evidence_sha256 ? "Yes" : "No"} · Model digest matches: ${result.model_digest === result.baseline_model_digest ? "Yes" : "No"}</p>
      <div class="experiment-response-pair">
        <div><strong>Control response</strong><p>${escapeHtml(result.baseline_summary || "No control summary stored.")}</p><small>${escapeHtml(result.baseline_classification || "Unknown")} · ${escapeHtml(result.baseline_confidence || "Unknown")}</small></div>
        <div><strong>Experimental response</strong><p>${escapeHtml(result.summary || result.error_message || "Awaiting worker")}</p><small>${escapeHtml(result.classification || "Unknown")} · ${escapeHtml(result.confidence || "Unknown")}</small></div>
      </div>
      ${result.evidence_mask?.length ? `<small>Removed: ${escapeHtml(result.evidence_mask.join(", "))}</small>` : ""}
      ${result.status === "complete" ? `
        <details>
          <summary>Record manual evaluation</summary>
          <form class="experiment-review form-grid" data-result="${escapeHtml(result.result_uid)}">
            ${["grounding", "completeness", "next_step_quality", "uncertainty", "usefulness"].map((field) =>
              `<label class="field"><span>${escapeHtml(field.replaceAll("_", " "))} (0-5)</span><input name="${field}_score" type="number" min="0" max="5" value="${result[`${field}_score`] ?? ""}"></label>`
            ).join("")}
            <label class="field"><span>Supported claims</span><input name="supported_claims" type="number" min="0" value="${result.supported_claims ?? ""}"></label>
            <label class="field"><span>Unsupported claims</span><input name="unsupported_claims" type="number" min="0" value="${result.unsupported_claims ?? ""}"></label>
            <label class="field"><span>Reviewer</span><input name="reviewer_name" value="${escapeHtml(result.reviewer_name || "")}"></label>
            <label class="field wide-field"><span>Notes</span><textarea name="reviewer_notes">${escapeHtml(result.reviewer_notes || "")}</textarea></label>
            <label><input name="missing_evidence_acknowledged" type="checkbox" ${result.missing_evidence_acknowledged ? "checked" : ""}> Model acknowledged missing evidence</label>
            <button type="submit">Save Evaluation</button>
          </form>
        </details>` : ""}
    </article>`).join("")}
      </div>
    </details>`;
  }).join("") || `<div class="empty">No results have been stored for this experiment.</div>`;
}

async function refresh() {
  runs = await jsonRequest(`/api/ai-experiments?limit=200&experiment_type=${type}`);
  renderRuns();
  if (selectedUid && runs.some((run) => run.experiment_uid === selectedUid)) await selectRun(selectedUid);
  els.updated.textContent = new Date().toLocaleTimeString();
}

async function queue(event) {
  event.preventDefault();
  let path;
  let body;
  if (isMissingEvidence) {
    const mask = [...document.querySelectorAll("input[name=mask]:checked")].map((input) => input.value);
    if (!mask.length) throw new Error("Select at least one evidence item to remove.");
    path = "/api/ai-experiments/missing-evidence";
    body = { comparison_uid: els.baseline.value, variants: [{ label: document.querySelector("#variant-label").value, mask }] };
  } else {
    const rows = [...document.querySelectorAll(".experiment-setting")];
    path = "/api/ai-experiments/stability";
    body = {
      comparison_uid: els.baseline.value,
      settings: rows.map((row) => ({
        label: row.querySelector("[name=setting-label]").value,
        temperature: Number(row.querySelector("[name=temperature]").value),
        seed: Number(row.querySelector("[name=seed]").value)
      }))
    };
  }
  const result = await jsonRequest(path, { method: "POST", body: JSON.stringify(body) });
  selectedUid = result.experiment_uid;
  els.status.textContent = `${result.experiment_uid} queued. You may close this page.`;
  await refresh();
}

configurePage();
els.form.addEventListener("submit", (event) => queue(event).catch((error) => { els.status.textContent = error.message; }));
els.refresh.addEventListener("click", () => refresh().catch((error) => { els.status.textContent = error.message; }));
els.runs.addEventListener("click", (event) => {
  const button = event.target.closest("[data-experiment]");
  if (button) selectRun(button.dataset.experiment).catch((error) => { els.status.textContent = error.message; });
});
els.detail.addEventListener("submit", async (event) => {
  const form = event.target.closest(".experiment-review");
  if (!form) return;
  event.preventDefault();
  const data = new FormData(form);
  const numeric = (name) => data.get(name) === "" ? null : Number(data.get(name));
  try {
    await jsonRequest(`/api/ai-experiment-results/${encodeURIComponent(form.dataset.result)}/review`, {
      method: "POST",
      body: JSON.stringify({
        grounding_score: numeric("grounding_score"),
        completeness_score: numeric("completeness_score"),
        next_step_quality_score: numeric("next_step_quality_score"),
        uncertainty_score: numeric("uncertainty_score"),
        usefulness_score: numeric("usefulness_score"),
        supported_claims: numeric("supported_claims"),
        unsupported_claims: numeric("unsupported_claims"),
        missing_evidence_acknowledged: data.get("missing_evidence_acknowledged") === "on",
        reviewer_name: data.get("reviewer_name"),
        reviewer_notes: data.get("reviewer_notes")
      })
    });
    els.status.textContent = "Manual evaluation saved.";
    await selectRun(selectedUid);
  } catch (error) {
    els.status.textContent = error.message;
  }
});
Promise.all([loadBaselines(), refresh()]).catch((error) => { els.status.textContent = error.message; });

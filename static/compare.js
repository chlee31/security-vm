const params = new URLSearchParams(window.location.search);
const requestedRun = params.get("run");
const requestedCase = params.get("case");

const els = {
  updated: document.querySelector("#compare-updated"),
  runs: document.querySelector("#cmp-runs"),
  pending: document.querySelector("#cmp-pending"),
  reviewed: document.querySelector("#cmp-reviewed"),
  neutral: document.querySelector("#cmp-neutral"),
  casesReviewed: document.querySelector("#cmp-cases-reviewed"),
  rejected: document.querySelector("#cmp-rejected"),
  runsList: document.querySelector("#cmp-runs-list"),
  filter: document.querySelector("#cmp-filter"),
  caseTitle: document.querySelector("#cmp-case-title"),
  modelState: document.querySelector("#cmp-model-state"),
  openCase: document.querySelector("#cmp-open-case"),
  useResponse: document.querySelector("#cmp-use-response"),
  reopenReview: document.querySelector("#cmp-reopen-review"),
  candidates: document.querySelector("#cmp-candidates"),
  voteForm: document.querySelector("#cmp-vote-form"),
  analyst: document.querySelector("#cmp-analyst"),
  notes: document.querySelector("#cmp-notes"),
  voteStatus: document.querySelector("#cmp-vote-status"),
  selectionSummary: document.querySelector("#cmp-selection-summary"),
  refresh: document.querySelector("#compare-refresh")
};
els.newForm = document.querySelector("#cmp-new-form");
els.newCase = document.querySelector("#cmp-new-case");
els.profileOptions = document.querySelector("#cmp-profile-options");
els.selectAll = document.querySelector("#cmp-select-all");
els.newStatus = document.querySelector("#cmp-new-status");
els.voteOptions = document.querySelector("#cmp-vote-options");

let state = { runs: [], selected: null, selectionSummary: null, filter: "all" };

async function getJson(path) {
  const response = await fetch(path, { cache: "no-store" });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.detail || `${path} returned ${response.status}`);
  return data;
}

async function sendJson(path, method, body) {
  const response = await fetch(path, {
    method,
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.detail || `${path} returned ${response.status}`);
  return data;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function label(value) {
  return String(value || "Unknown").replaceAll("_", " ").replace(/\b\w/g, (char) => char.toUpperCase());
}

function setStatus(kind, message) {
  els.voteStatus.className = `connection-status ${kind || ""}`.trim();
  els.voteStatus.textContent = message;
}

function renderRuns() {
  const reviewed = state.runs.filter((run) => Number(run.vote_count) > 0).length;
  els.runs.textContent = state.runs.length;
  els.pending.textContent = state.runs.length - reviewed;
  els.reviewed.textContent = reviewed;
  const visible = state.runs.filter((run) => {
    if (state.filter === "all") return true;
    if (state.filter === "pending") return !run.selection && !["failed"].includes(run.status);
    if (state.filter === "reviewed") return /^R\d+$/.test(run.selection || "") || /^[A-Z]$/.test(run.selection || "");
    if (state.filter === "rejected") return run.selection === "reject_all";
    if (state.filter === "tie") return run.selection === "tie";
    if (state.filter === "failed") return ["failed", "partial"].includes(run.status);
    return true;
  });
  els.runsList.innerHTML = visible.map((run) => `
    <button class="comparison-run-button ${state.selected?.comparison_uid === run.comparison_uid ? "selected" : ""}" type="button" data-run="${escapeHtml(run.comparison_uid)}">
      <span>
        <strong>${escapeHtml(run.case_uid)}</strong>
        <small>${escapeHtml(run.comparison_uid)} · ${run.candidate_count || 0}/${run.expected_candidate_count || run.processed_count || 0} successful · ${run.processed_count || 0}/${run.expected_candidate_count || run.processed_count || 0} attempted</small>
      </span>
      <span class="status-pill ${run.vote_count ? "active" : ""}">${run.selection ? label(run.selection) : label(run.status)}</span>
    </button>
  `).join("") || `<div class="empty">No comparisons match this view.</div>`;
}

function renderModelThreatIntel(candidate) {
  const analysis = candidate.threat_intel_analysis || {};
  return `
    <section class="candidate-threat-intel">
      <div class="candidate-section-heading">
        <h3>Threat Intelligence Interpretation</h3>
        <span class="status-pill">${escapeHtml(label(analysis.influence || "unavailable"))}</span>
      </div>
      <p>${escapeHtml(analysis.overall || "This legacy response did not include a dedicated threat-intelligence conclusion.")}</p>
    </section>
  `;
}

function renderThreatIntelEvidence(evidence) {
  if (!evidence || !Object.keys(evidence).length) {
    return `<div class="empty">This legacy comparison has no stored threat-intelligence evidence snapshot.</div>`;
  }
  const observables = [];
  if (evidence.src_ip) observables.push({ label: "Source IP", value: evidence.src_ip.indicator, ...evidence.src_ip });
  if (evidence.dest_ip) observables.push({ label: "Destination IP", value: evidence.dest_ip.indicator, ...evidence.dest_ip });
  for (const item of evidence.alert_observables || []) observables.push({ label: label(item.indicator_type), value: item.indicator, ...item });
  return `
    <section class="comparison-threat-intel">
      <div class="comparison-inline-head">
        <div><strong>Shared Threat-Intelligence Evidence</strong><small>Exact sanitized provider results supplied to every response.</small></div>
      </div>
      <div class="comparison-provider-matrix">
        ${(evidence.provider_status || []).map((provider) => {
          const findings = observables.flatMap((observable) =>
            (observable.providers || []).filter((item) => item.name === provider.name).map((item) => ({ observable, item }))
          );
          const matched = findings.filter(({ item }) => item.result === "matched");
          const stateName = provider.name === "virustotal" && provider.enabled
            ? "not_requested"
            : matched.length ? "matched" : provider.enabled ? "no_match" : "not_active";
          return `
            <article class="comparison-provider ${stateName}">
              <header><strong>${escapeHtml(provider.label || label(provider.name))}</strong><span>${escapeHtml(label(stateName))}</span></header>
              <small>${provider.enabled ? `${provider.indicator_count || 0} cached indicators · ${escapeHtml(label(provider.status))}` : "Provider not active"}</small>
              ${matched.map(({ observable, item }) => `<p><b>${escapeHtml(observable.label)} ${escapeHtml(observable.value || "unknown")}</b>: ${(item.matches || []).map((match) => escapeHtml(`${match.category || "indicator match"}${match.confidence != null ? ` (${match.confidence}% confidence)` : ""}${match.malware_family ? ` · ${match.malware_family}` : ""}`)).join(" · ")}</p>`).join("") || `<p>No supplied observable matched this provider.</p>`}
            </article>
          `;
        }).join("")}
      </div>
    </section>
  `;
}

function renderCandidates() {
  const detail = state.selected;
  if (!detail) {
    els.candidates.innerHTML = `<div class="empty">Choose a case comparison from the review queue.</div>`;
    els.voteForm.hidden = true;
    els.useResponse.hidden = true;
    return;
  }
  const vote = detail.votes?.[0];
  const outcome = detail.review_outcome || {};
  const winner = outcome.winner;
  const activeExplanation = detail.active_case_explanation;
  const selectedResponseIsActive = Boolean(
    winner
      && activeExplanation
      && activeExplanation.comparison_uid === detail.comparison_uid
      && activeExplanation.anonymous_slot === winner.anonymous_slot
  );
  els.caseTitle.textContent = detail.case_uid;
  els.openCase.href = `/investigation?case=${encodeURIComponent(detail.case_uid)}`;
  els.openCase.hidden = false;
  els.reopenReview.hidden = !vote;
  els.useResponse.hidden = !winner;
  els.useResponse.disabled = selectedResponseIsActive;
  els.useResponse.textContent = selectedResponseIsActive
    ? "Selected Response Is Used on Case"
    : "Use Selected Response on Case";
  els.modelState.textContent = winner
    ? `${vote.analyst_name || "Analyst"} selected Response ${winner.anonymous_slot}: ${winner.model_identity || winner.model_name}`
    : vote
    ? `${vote.analyst_name || "Analyst"} recorded ${label(vote.selection)}`
    : "Responses use anonymous R labels until review.";
  const selectable = (detail.candidates || []).filter((candidate) => candidate.status === "complete");
  els.voteOptions.innerHTML = selectable.map((candidate, index) => `
    <label><input type="radio" name="selection" value="${escapeHtml(candidate.anonymous_slot)}" ${index === 0 ? "required" : ""}><span>Response ${escapeHtml(candidate.anonymous_slot)}</span></label>
  `).join("") + `
    <label><input type="radio" name="selection" value="tie"><span>Tie</span></label>
    <label><input type="radio" name="selection" value="reject_all"><span>Reject All</span></label>
  `;
  els.candidates.innerHTML = `
    ${renderThreatIntelEvidence(detail.threat_intel_evidence)}
    ${renderComparisonInputProof(detail)}
    <div class="model-candidate-grid comparison-response-grid">
    ${(detail.candidates || []).map((candidate) => `
    <article class="model-candidate ${vote?.selection === candidate.anonymous_slot ? "winner" : ""} ${candidate.status === "failed" ? "failed" : ""}">
      <header>
        <span class="candidate-letter">${escapeHtml(candidate.anonymous_slot)}</span>
        <div>
          <strong>Response ${escapeHtml(candidate.anonymous_slot)}</strong>
          <small>${candidate.status === "failed" ? "Request failed" : `${candidate.elapsed_ms ?? 0}ms`}</small>
          ${winner?.anonymous_slot === candidate.anonymous_slot ? `<small class="winner-identity">${escapeHtml(winner.model_identity || winner.model_name || "Selected model")}</small>` : ""}
        </div>
        ${vote?.selection === candidate.anonymous_slot ? `<span class="status-pill active">selected</span>` : ""}
      </header>
      ${candidate.status === "failed" ? `
        <div class="empty">This model request failed. It cannot be selected.</div>
      ` : `
        <div class="candidate-verdict">
          <strong>${escapeHtml(candidate.classification || "No classification")}</strong>
          <span>${escapeHtml(candidate.confidence || "Unknown")} confidence</span>
        </div>
        <section>
          <h3>Case Summary</h3>
          <p>${escapeHtml(candidate.summary || "No summary returned.")}</p>
        </section>
        ${renderModelThreatIntel(candidate)}
        <dl class="candidate-evidence">
          <div><dt>Who</dt><dd>${escapeHtml(candidate.who_summary || "Not established")}</dd></div>
          <div><dt>What</dt><dd>${escapeHtml(candidate.what_summary || "Not established")}</dd></div>
          <div><dt>When</dt><dd>${escapeHtml(candidate.when_summary || "Not established")}</dd></div>
          <div><dt>Where</dt><dd>${escapeHtml(candidate.where_summary || "Not established")}</dd></div>
          <div><dt>Why</dt><dd>${escapeHtml(candidate.why_summary || "Not established")}</dd></div>
          <div><dt>How</dt><dd>${escapeHtml(candidate.how_summary || "Not established")}</dd></div>
        </dl>
        <section class="candidate-next-steps">
          <h3>Recommended Next Steps</h3>
          <ol>${(candidate.next_steps || []).map((step) => `<li>${escapeHtml(step)}</li>`).join("") || `<li>No concrete next steps returned.</li>`}</ol>
        </section>
        <details class="model-raw-response"><summary>View complete raw model response</summary><pre class="raw-json">${escapeHtml(candidate.raw_response || "No raw response stored.")}</pre></details>
        <footer>Response ${escapeHtml(candidate.anonymous_slot)} · prompt ${escapeHtml(candidate.prompt_version || "unknown")}</footer>
      `}
    </article>
    `).join("")}
    </div>
  `;
  els.voteForm.hidden = Boolean(vote) || detail.status === "failed";
  if (vote) {
    setStatus(
      "ok",
      selectedResponseIsActive
        ? `Response ${winner.anonymous_slot} is the analyst-approved explanation displayed on the case.`
        : winner
        ? `Review complete. Response ${winner.anonymous_slot} was ${winner.model_identity || winner.model_name}.`
        : `Review complete. Selection: ${label(vote.selection)}.`
    );
  } else if (detail.status === "partial") {
    setStatus("", "A partial comparison completed. Vote among the available responses or reject all.");
  } else {
    setStatus("", "Read all three model responses before recording the most useful one.");
  }
}

function renderComparisonInputProof(detail) {
  const proof = detail?.input_consistency || {};
  const fullyVerified = proof.same_prompt_across_candidates
    && proof.same_evidence_across_candidates
    && proof.same_generation_options_across_candidates;
  const matchesInitial = proof.matches_initial_case_prompt
    && proof.matches_initial_case_evidence;
  return `
    <section class="comparison-input-proof ${fullyVerified ? "verified" : "warning"}">
      <div>
        <strong>${fullyVerified ? "Verified identical input for every response" : "Comparison input could not be fully verified"}</strong>
        <small>${matchesInitial
          ? "These responses use the exact prompt and evidence snapshot that produced the initial case summary."
          : "The initial case summary used a different evidence snapshot. Compare the responses as separate assessments."}</small>
      </div>
      <details>
        <summary>View input hashes and snapshot time</summary>
        <p>Prompt SHA-256: <span class="hash-value">${escapeHtml(proof.prompt_sha256 || "not recorded")}</span></p>
        <p>Evidence SHA-256: <span class="hash-value">${escapeHtml(proof.evidence_sha256 || "not recorded")}</span></p>
        <p>Initial snapshot: ${escapeHtml(proof.initial_prepared_at || "not recorded")}</p>
      </details>
    </section>
  `;
}

function renderSelectionSummary() {
  const summary = state.selectionSummary || { models: [], votes: 0, ties: 0, rejected: 0 };
  els.neutral.textContent = Number(summary.ties || 0) + Number(summary.rejected || 0);
  els.casesReviewed.textContent = Number(summary.reviewed_cases || 0);
  els.rejected.textContent = Number(summary.rejected || 0);
  const decisiveVotes = Math.max(1, Number(summary.votes || 0) - Number(summary.ties || 0) - Number(summary.rejected || 0));
  els.selectionSummary.innerHTML = (summary.models || []).map((model, index) => `
    <div class="workbook-row selection-summary-row">
      <div class="row tight">
        <strong>${index + 1}. ${escapeHtml(model.model_identity || model.model_name || "Unknown model")}</strong>
        <span>${model.wins} selection${model.wins === 1 ? "" : "s"}</span>
      </div>
      <p>${escapeHtml(model.model_provider || "unknown provider")} · profile ${escapeHtml(model.ai_profile_uid)}</p>
      <div class="bar"><span style="--value:${(Number(model.wins) / decisiveVotes) * 100}%"></span></div>
      <small>${Math.round((Number(model.wins) / decisiveVotes) * 100)}% of decisive model selections</small>
    </div>
  `).join("") || `<div class="empty">No model selections have been submitted yet.</div>`;
}

async function selectRun(uid) {
  state.selected = await getJson(`/api/ai-comparisons/${encodeURIComponent(uid)}`);
  history.replaceState(null, "", `/compare?run=${encodeURIComponent(uid)}&case=${encodeURIComponent(state.selected.case_uid)}`);
  renderRuns();
  renderCandidates();
}

async function submitVote(event) {
  event.preventDefault();
  if (!state.selected) return;
  const selection = new FormData(els.voteForm).get("selection");
  if (!selection) {
    setStatus("error", "Select one response, Tie, or Reject All.");
    return;
  }
  try {
    state.selected = await sendJson(
      `/api/ai-comparisons/${encodeURIComponent(state.selected.comparison_uid)}/vote`,
      "POST",
      { analyst_name: els.analyst.value, selection, notes: els.notes.value }
    );
    state.selectionSummary = await getJson("/api/ai-comparisons/selection-summary");
    const run = state.runs.find((item) => item.comparison_uid === state.selected.comparison_uid);
    if (run) run.vote_count = 1;
    renderRuns();
    renderCandidates();
    renderSelectionSummary();
  } catch (error) {
    setStatus("error", error.message);
  }
}

async function reopenReview() {
  if (!state.selected) return;
  if (!window.confirm("Reopen this review? The previous selection will remain in review history.")) return;
  try {
    state.selected = await sendJson(
      `/api/ai-comparisons/${encodeURIComponent(state.selected.comparison_uid)}/reopen`,
      "POST"
    );
    state.selectionSummary = await getJson("/api/ai-comparisons/selection-summary");
    const run = state.runs.find((item) => item.comparison_uid === state.selected.comparison_uid);
    if (run) {
      run.vote_count = 0;
      run.selection = null;
      run.analyst_name = null;
      run.reviewed_at = null;
    }
    renderRuns();
    renderCandidates();
    renderSelectionSummary();
  } catch (error) {
    setStatus("error", error.message);
  }
}

async function useSelectedResponse() {
  if (!state.selected?.review_outcome?.winner) return;
  const winner = state.selected.review_outcome.winner;
  if (!window.confirm(
    `Use Response ${winner.anonymous_slot} as the displayed AI explanation on ${state.selected.case_uid}?`
  )) return;
  els.useResponse.disabled = true;
  try {
    state.selected = await sendJson(
      `/api/ai-comparisons/${encodeURIComponent(state.selected.comparison_uid)}/use-as-case-explanation`,
      "POST",
      {
        analyst_name: els.analyst.value || state.selected.review_outcome.analyst_name || "analyst",
        notes: els.notes.value || "Promoted from reviewed model comparison"
      }
    );
    renderCandidates();
    setStatus("ok", "The selected response is now the AI explanation shown on the case page.");
  } catch (error) {
    els.useResponse.disabled = false;
    setStatus("error", error.message);
  }
}

async function refresh() {
  els.refresh.disabled = true;
  try {
    const query = requestedCase ? `?limit=100&case_uid=${encodeURIComponent(requestedCase)}` : "?limit=100";
    [state.runs, state.selectionSummary] = await Promise.all([
      getJson(`/api/ai-comparisons${query}`),
      getJson("/api/ai-comparisons/selection-summary")
    ]);
    const selectedUid = state.selected?.comparison_uid || requestedRun || state.runs[0]?.comparison_uid;
    if (selectedUid) state.selected = await getJson(`/api/ai-comparisons/${encodeURIComponent(selectedUid)}`);
    renderRuns();
    renderCandidates();
    renderSelectionSummary();
    els.updated.textContent = new Date().toLocaleTimeString();
  } catch (error) {
    els.updated.textContent = "Comparison API error";
    setStatus("error", error.message);
  } finally {
    els.refresh.disabled = false;
  }
}

async function loadComparisonOptions() {
  const options = await getJson("/api/ai-comparisons/options?limit=200");
  const active = options.profiles || [];
  els.profileOptions.innerHTML = active.map((profile) => `
    <label><input type="checkbox" name="profile_uid" value="${escapeHtml(profile.uid)}" checked>
      <span>${escapeHtml(profile.name)} · ${escapeHtml(profile.model)}</span>
    </label>
  `).join("") || `<div class="empty">No active AI profiles are configured.</div>`;
  els.newCase.innerHTML = (options.cases || []).map((item) => `
    <option value="${escapeHtml(item.case_uid)}">${escapeHtml(item.case_uid)} · ${escapeHtml(item.signature || item.detection_type || "case")}</option>
  `).join("");
}

async function queueComparison(event) {
  event.preventDefault();
  const profileUids = [...els.profileOptions.querySelectorAll("input:checked")].map((input) => input.value);
  if (!profileUids.length) {
    els.newStatus.textContent = "Select at least one active profile.";
    return;
  }
  try {
    const queued = await sendJson(
      `/api/cases/${encodeURIComponent(els.newCase.value)}/ai-comparison`,
      "POST",
      { profile_uids: profileUids }
    );
    els.newStatus.textContent = `${queued.comparison_uid} queued. The background worker will run ${queued.expected_candidate_count} requests sequentially.`;
    await refresh();
  } catch (error) {
    els.newStatus.textContent = error.message;
  }
}

els.runsList.addEventListener("click", (event) => {
  const button = event.target.closest("[data-run]");
  if (!button) return;
  selectRun(button.dataset.run).catch((error) => setStatus("error", error.message));
});
els.voteForm.addEventListener("submit", submitVote);
els.refresh.addEventListener("click", refresh);
els.reopenReview.addEventListener("click", reopenReview);
els.useResponse.addEventListener("click", useSelectedResponse);
els.filter.addEventListener("change", () => {
  state.filter = els.filter.value;
  renderRuns();
});
els.newForm.addEventListener("submit", queueComparison);
els.selectAll.addEventListener("click", () => {
  els.profileOptions.querySelectorAll("input").forEach((input) => { input.checked = true; });
});
Promise.all([loadComparisonOptions(), refresh()]).catch((error) => setStatus("error", error.message));

const params = new URLSearchParams(window.location.search);
const requestedRun = params.get("run");
const requestedCase = params.get("case");

const els = {
  updated: document.querySelector("#compare-updated"),
  runs: document.querySelector("#cmp-runs"),
  pending: document.querySelector("#cmp-pending"),
  reviewed: document.querySelector("#cmp-reviewed"),
  neutral: document.querySelector("#cmp-neutral"),
  runsList: document.querySelector("#cmp-runs-list"),
  caseTitle: document.querySelector("#cmp-case-title"),
  modelState: document.querySelector("#cmp-model-state"),
  candidates: document.querySelector("#cmp-candidates"),
  voteForm: document.querySelector("#cmp-vote-form"),
  analyst: document.querySelector("#cmp-analyst"),
  notes: document.querySelector("#cmp-notes"),
  voteStatus: document.querySelector("#cmp-vote-status"),
  scorecard: document.querySelector("#cmp-scorecard"),
  refresh: document.querySelector("#compare-refresh")
};

let state = { runs: [], selected: null, scorecard: null };

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
  els.runsList.innerHTML = state.runs.map((run) => `
    <button class="comparison-run-button ${state.selected?.comparison_uid === run.comparison_uid ? "selected" : ""}" type="button" data-run="${escapeHtml(run.comparison_uid)}">
      <span>
        <strong>${escapeHtml(run.case_uid)}</strong>
        <small>${escapeHtml(run.comparison_uid)} · ${run.candidate_count || 0}/3 responses</small>
      </span>
      <span class="status-pill ${run.vote_count ? "active" : ""}">${run.vote_count ? "reviewed" : label(run.status)}</span>
    </button>
  `).join("") || `<div class="empty">No model comparisons yet. Start one from a case investigation.</div>`;
}

function candidateIdentity(candidate) {
  return `${candidate.model_provider || "unknown"}:${candidate.model_name || candidate.model_identity || "unknown"} · profile ${candidate.ai_profile_uid || "unknown"}`;
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
        <div><strong>Shared Threat-Intelligence Evidence</strong><small>Exact sanitized provider results supplied to Responses A, B, and C.</small></div>
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
    return;
  }
  const vote = detail.votes?.[0];
  els.caseTitle.textContent = detail.case_uid;
  els.modelState.textContent = vote
    ? `${vote.analyst_name || "Analyst"} selected ${label(vote.selection)}`
    : "Model identities and complete responses are visible";
  els.candidates.innerHTML = `
    ${renderThreatIntelEvidence(detail.threat_intel_evidence)}
    <div class="model-candidate-grid comparison-response-grid">
    ${(detail.candidates || []).map((candidate) => `
    <article class="model-candidate ${vote?.selection === candidate.anonymous_slot ? "winner" : ""} ${candidate.status === "failed" ? "failed" : ""}">
      <header>
        <span class="candidate-letter">${escapeHtml(candidate.anonymous_slot)}</span>
        <div>
          <strong>Response ${escapeHtml(candidate.anonymous_slot)}</strong>
          <small>${escapeHtml(candidateIdentity(candidate))}</small>
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
        <footer>Adjustment ${candidate.risk_adjustment ?? 0} · ${candidate.elapsed_ms ?? 0}ms · run ${escapeHtml(candidate.model_run_id || "not recorded")}</footer>
      `}
    </article>
    `).join("")}
    </div>
  `;
  els.voteForm.hidden = Boolean(vote) || detail.status === "failed";
  if (vote) {
    setStatus("ok", `Review complete. Selection: ${label(vote.selection)}.`);
  } else if (detail.status === "partial") {
    setStatus("", "A partial comparison completed. Vote among the available responses or reject all.");
  } else {
    setStatus("", "Read all three model responses before recording the most useful one.");
  }
}

function renderScorecard() {
  const scorecard = state.scorecard || { models: [], votes: 0, ties: 0, rejected: 0 };
  els.neutral.textContent = Number(scorecard.ties || 0) + Number(scorecard.rejected || 0);
  const decisiveVotes = Math.max(1, Number(scorecard.votes || 0) - Number(scorecard.ties || 0) - Number(scorecard.rejected || 0));
  els.scorecard.innerHTML = (scorecard.models || []).map((model, index) => `
    <div class="workbook-row scorecard-row">
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
    setStatus("error", "Select Response A, B, C, Tie, or Reject All.");
    return;
  }
  try {
    state.selected = await sendJson(
      `/api/ai-comparisons/${encodeURIComponent(state.selected.comparison_uid)}/vote`,
      "POST",
      { analyst_name: els.analyst.value, selection, notes: els.notes.value }
    );
    state.scorecard = await getJson("/api/ai-comparisons/scorecard");
    const run = state.runs.find((item) => item.comparison_uid === state.selected.comparison_uid);
    if (run) run.vote_count = 1;
    renderRuns();
    renderCandidates();
    renderScorecard();
  } catch (error) {
    setStatus("error", error.message);
  }
}

async function refresh() {
  els.refresh.disabled = true;
  try {
    const query = requestedCase ? `?limit=100&case_uid=${encodeURIComponent(requestedCase)}` : "?limit=100";
    [state.runs, state.scorecard] = await Promise.all([
      getJson(`/api/ai-comparisons${query}`),
      getJson("/api/ai-comparisons/scorecard")
    ]);
    const selectedUid = state.selected?.comparison_uid || requestedRun || state.runs[0]?.comparison_uid;
    if (selectedUid) state.selected = await getJson(`/api/ai-comparisons/${encodeURIComponent(selectedUid)}`);
    renderRuns();
    renderCandidates();
    renderScorecard();
    els.updated.textContent = new Date().toLocaleTimeString();
  } catch (error) {
    els.updated.textContent = "Comparison API error";
    setStatus("error", error.message);
  } finally {
    els.refresh.disabled = false;
  }
}

els.runsList.addEventListener("click", (event) => {
  const button = event.target.closest("[data-run]");
  if (!button) return;
  selectRun(button.dataset.run).catch((error) => setStatus("error", error.message));
});
els.voteForm.addEventListener("submit", submitVote);
els.refresh.addEventListener("click", refresh);
refresh();

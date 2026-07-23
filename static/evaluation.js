const state = {
  view: location.pathname.split("/").filter(Boolean).pop() || "overview",
  overview: null,
  scenarios: [],
  cases: [],
  selectedScenario: null,
  editingScenario: null,
  comparisons: []
};

if (state.view === "evaluation") state.view = "overview";

const els = {
  state: document.querySelector("#evaluation-state"),
  status: document.querySelector("#evaluation-status"),
  metrics: document.querySelector("#evaluation-metrics"),
  recent: document.querySelector("#evaluation-recent"),
  scenarioForm: document.querySelector("#scenario-form"),
  scenarioFormTitle: document.querySelector("#scenario-form-title"),
  scenarioUid: document.querySelector("#scenario-uid"),
  scenarioName: document.querySelector("#scenario-name"),
  scenarioExperiment: document.querySelector("#scenario-experiment"),
  scenarioGroundTruth: document.querySelector("#scenario-ground-truth"),
  scenarioAuthorized: document.querySelector("#scenario-authorized"),
  scenarioSucceeded: document.querySelector("#scenario-succeeded"),
  scenarioSourceIp: document.querySelector("#scenario-source-ip"),
  scenarioDestinationIp: document.querySelector("#scenario-destination-ip"),
  scenarioStart: document.querySelector("#scenario-start"),
  scenarioEnd: document.querySelector("#scenario-end"),
  scenarioCaseCount: document.querySelector("#scenario-case-count"),
  scenarioSuricata: document.querySelector("#scenario-suricata"),
  scenarioZeek: document.querySelector("#scenario-zeek"),
  scenarioMin: document.querySelector("#scenario-min-classification"),
  scenarioMax: document.querySelector("#scenario-max-classification"),
  scenarioNotes: document.querySelector("#scenario-notes"),
  scenarioSave: document.querySelector("#scenario-save"),
  scenarioCancel: document.querySelector("#scenario-cancel"),
  scenarioRefresh: document.querySelector("#scenario-refresh"),
  scenarioList: document.querySelector("#scenario-list"),
  scenarioDetailPanel: document.querySelector("#scenario-detail-panel"),
  scenarioDetailTitle: document.querySelector("#scenario-detail-title"),
  scenarioDelete: document.querySelector("#scenario-delete"),
  scenarioJsonExport: document.querySelector("#scenario-json-export"),
  scenarioCsvExport: document.querySelector("#scenario-csv-export"),
  caseLinkForm: document.querySelector("#case-link-form"),
  caseLinkUid: document.querySelector("#case-link-uid"),
  caseLinkStatus: document.querySelector("#case-link-status"),
  caseLinkConfirmed: document.querySelector("#case-link-confirmed"),
  caseLinkNotes: document.querySelector("#case-link-notes"),
  caseLinkList: document.querySelector("#case-link-list"),
  correlationScenario: document.querySelector("#correlation-scenario"),
  correlationMetrics: document.querySelector("#correlation-metrics"),
  eventLabelForm: document.querySelector("#event-label-form"),
  eventSensor: document.querySelector("#event-sensor"),
  eventUid: document.querySelector("#event-uid"),
  eventCaseUid: document.querySelector("#event-case-uid"),
  eventLabel: document.querySelector("#event-label"),
  eventNotes: document.querySelector("#event-notes"),
  eventOptions: document.querySelector("#scenario-event-options"),
  caseOptions: document.querySelector("#case-uid-options"),
  eventLabelList: document.querySelector("#event-label-list"),
  scoringCases: document.querySelector("#scoring-case-list"),
  scoringRunCount: document.querySelector("#scoring-run-count"),
  modelRunCount: document.querySelector("#model-run-count"),
  modelRunList: document.querySelector("#model-run-list")
};

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function label(value) {
  return String(value || "unknown")
    .replaceAll("_", " ")
    .replace(/\b\w/g, (character) => character.toUpperCase());
}

function localDateTime(value) {
  if (!value) return "Not recorded";
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : date.toLocaleString();
}

function inputDateTime(date) {
  const pad = (value) => String(value).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

function triState(value) {
  if (value === true) return "true";
  if (value === false) return "false";
  return "";
}

function triStatePayload(value) {
  if (value === "true") return true;
  if (value === "false") return false;
  return null;
}

async function getJson(url) {
  const response = await fetch(url, { cache: "no-store" });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.detail || `${url} returned ${response.status}`);
  return body;
}

async function sendJson(url, method, payload) {
  const response = await fetch(url, {
    method,
    headers: { "Content-Type": "application/json" },
    body: payload == null ? undefined : JSON.stringify(payload)
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.detail || `${method} ${url} returned ${response.status}`);
  return body;
}

function setStatus(kind, message) {
  els.status.className = `connection-status ${kind || ""}`;
  els.status.textContent = message;
}

function activateView() {
  document.querySelectorAll("[data-evaluation-view]").forEach((link) => {
    link.classList.toggle("active", link.dataset.evaluationView === state.view);
  });
  document.querySelectorAll(".evaluation-view").forEach((view) => {
    view.hidden = view.dataset.view !== state.view;
  });
}

function renderOverview() {
  const data = state.overview || {};
  const metrics = [
    ["Scenarios", data.scenarios || 0, "Manual ground truth"],
    ["Linked Cases", data.case_links || 0, "Operational cases referenced"],
    ["Event Labels", data.event_labels || 0, "Membership decisions"],
    ["Model Runs", data.comparison_runs || 0, "Existing comparisons"],
    ["Scoring Runs", data.scoring_runs || 0, "Evaluation only"]
  ];
  els.metrics.innerHTML = metrics.map(([name, value, note]) => `
    <article class="metric">
      <span>${escapeHtml(name)}</span>
      <strong>${escapeHtml(value)}</strong>
      <small>${escapeHtml(note)}</small>
    </article>
  `).join("");
  els.recent.innerHTML = (data.recent_scenarios || []).map((scenario) => `
    <a class="workbook-row evaluation-scenario-link" href="/evaluation/scenarios?scenario=${encodeURIComponent(scenario.scenario_uid)}">
      <div class="row tight"><strong>${escapeHtml(scenario.scenario_uid)}</strong><span>${escapeHtml(label(scenario.experiment_type))}</span></div>
      <p>${escapeHtml(scenario.name)}</p>
      <small>${localDateTime(scenario.start_time)} · ${scenario.linked_case_count || 0} linked cases</small>
    </a>
  `).join("") || `<div class="empty">No evaluation scenarios have been recorded.</div>`;
}

function scenarioPayload() {
  return {
    scenario_uid: els.scenarioUid.value,
    name: els.scenarioName.value,
    experiment_type: els.scenarioExperiment.value,
    ground_truth_class: els.scenarioGroundTruth.value,
    authorized_activity: triStatePayload(els.scenarioAuthorized.value),
    attack_succeeded: triStatePayload(els.scenarioSucceeded.value),
    source_ip: els.scenarioSourceIp.value,
    destination_ip: els.scenarioDestinationIp.value,
    start_time: els.scenarioStart.value,
    end_time: els.scenarioEnd.value,
    expected_case_count: Number(els.scenarioCaseCount.value || 0),
    expected_min_classification: els.scenarioMin.value,
    expected_max_classification: els.scenarioMax.value,
    expected_sensors: [
      els.scenarioSuricata.checked ? "suricata" : null,
      els.scenarioZeek.checked ? "zeek" : null
    ].filter(Boolean),
    notes: els.scenarioNotes.value
  };
}

function resetScenarioForm() {
  state.editingScenario = null;
  els.scenarioForm.reset();
  els.scenarioUid.disabled = false;
  els.scenarioCaseCount.value = "1";
  els.scenarioSuricata.checked = true;
  els.scenarioZeek.checked = true;
  const now = new Date();
  const end = new Date(now.getTime() + 5 * 60 * 1000);
  els.scenarioStart.value = inputDateTime(now);
  els.scenarioEnd.value = inputDateTime(end);
  els.scenarioFormTitle.textContent = "Create Scenario";
  els.scenarioSave.textContent = "Create Scenario";
}

function editScenario(scenario) {
  state.editingScenario = scenario.scenario_uid;
  els.scenarioUid.value = scenario.scenario_uid;
  els.scenarioUid.disabled = true;
  els.scenarioName.value = scenario.name || "";
  els.scenarioExperiment.value = scenario.experiment_type || "correlation";
  els.scenarioGroundTruth.value = scenario.ground_truth_class || "";
  els.scenarioAuthorized.value = triState(scenario.authorized_activity);
  els.scenarioSucceeded.value = triState(scenario.attack_succeeded);
  els.scenarioSourceIp.value = scenario.source_ip || "";
  els.scenarioDestinationIp.value = scenario.destination_ip || "";
  els.scenarioStart.value = inputDateTime(new Date(scenario.start_time));
  els.scenarioEnd.value = inputDateTime(new Date(scenario.end_time));
  els.scenarioCaseCount.value = scenario.expected_case_count ?? 1;
  els.scenarioSuricata.checked = (scenario.expected_sensors || []).includes("suricata");
  els.scenarioZeek.checked = (scenario.expected_sensors || []).includes("zeek");
  els.scenarioMin.value = scenario.expected_min_classification || "";
  els.scenarioMax.value = scenario.expected_max_classification || "";
  els.scenarioNotes.value = scenario.notes || "";
  els.scenarioFormTitle.textContent = `Edit ${scenario.scenario_uid}`;
  els.scenarioSave.textContent = "Save Scenario";
  els.scenarioForm.scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderScenarioList() {
  els.scenarioList.innerHTML = state.scenarios.map((scenario) => `
    <article class="workbook-row evaluation-scenario ${state.selectedScenario?.scenario_uid === scenario.scenario_uid ? "selected" : ""}" data-scenario-uid="${escapeHtml(scenario.scenario_uid)}">
      <div class="row tight">
        <strong>${escapeHtml(scenario.scenario_uid)}</strong>
        <span>${escapeHtml(label(scenario.experiment_type))}</span>
      </div>
      <p>${escapeHtml(scenario.name)}</p>
      <small>${escapeHtml(scenario.ground_truth_class)} · ${scenario.linked_case_count || 0} cases · ${scenario.event_label_count || 0} event labels</small>
      <div class="evaluation-row-actions">
        <button type="button" data-scenario-open="${escapeHtml(scenario.scenario_uid)}">Open</button>
        <button type="button" data-scenario-edit="${escapeHtml(scenario.scenario_uid)}">Edit</button>
      </div>
    </article>
  `).join("") || `<div class="empty">No saved scenarios.</div>`;
}

function renderCaseOptions() {
  els.caseLinkUid.innerHTML = `<option value="">Select a case</option>` + state.cases.map((item) => `
    <option value="${escapeHtml(item.case_uid)}">${escapeHtml(item.case_uid)} · ${escapeHtml(label(item.detection_type))} · ${escapeHtml(item.final_classification || "pending")}</option>
  `).join("");
  els.caseOptions.innerHTML = state.cases.map((item) => `<option value="${escapeHtml(item.case_uid)}"></option>`).join("");
}

function renderScenarioDetail() {
  const scenario = state.selectedScenario;
  els.scenarioDetailPanel.hidden = !scenario;
  if (!scenario) return;
  els.scenarioDetailTitle.textContent = `${scenario.scenario_uid} · ${scenario.name}`;
  els.scenarioJsonExport.href = `/api/evaluation/export?format=json&scenario_uid=${encodeURIComponent(scenario.scenario_uid)}`;
  els.scenarioCsvExport.href = `/api/evaluation/export?format=csv&scenario_uid=${encodeURIComponent(scenario.scenario_uid)}`;
  els.caseLinkList.innerHTML = `
    <table class="evaluation-table">
      <thead><tr><th>Case</th><th>Relationship</th><th>Operational result</th><th>Confirmed</th><th></th></tr></thead>
      <tbody>${(scenario.case_links || []).map((link) => `
        <tr>
          <td><a class="inline-link" href="/investigation?case=${encodeURIComponent(link.case_uid)}" target="_blank" rel="noopener">${escapeHtml(link.case_uid)}</a><small>${escapeHtml(link.notes || "No notes")}</small></td>
          <td>${escapeHtml(label(link.relationship_status))}</td>
          <td>${escapeHtml(link.final_classification || (link.case_exists ? "Pending" : "Case unavailable"))}</td>
          <td>${link.analyst_confirmed ? "Yes" : "No"}</td>
          <td><button class="danger-button compact-command" type="button" data-case-unlink="${escapeHtml(link.case_uid)}">Unlink</button></td>
        </tr>
      `).join("") || `<tr><td colspan="5">No cases linked.</td></tr>`}</tbody>
    </table>
  `;
}

async function selectScenario(uid) {
  state.selectedScenario = await getJson(`/api/evaluation/scenarios/${encodeURIComponent(uid)}`);
  renderScenarioList();
  renderScenarioDetail();
  if (state.view === "correlation") await renderCorrelation();
}

async function saveScenario(event) {
  event.preventDefault();
  try {
    const payload = scenarioPayload();
    const editing = state.editingScenario;
    const url = editing
      ? `/api/evaluation/scenarios/${encodeURIComponent(editing)}`
      : "/api/evaluation/scenarios";
    const saved = await sendJson(url, editing ? "PUT" : "POST", payload);
    setStatus("ok", `${saved.scenario_uid} saved. Operational case data was not modified.`);
    resetScenarioForm();
    await refreshFoundation();
    await selectScenario(saved.scenario_uid);
  } catch (error) {
    setStatus("error", error.message);
  }
}

async function saveCaseLink(event) {
  event.preventDefault();
  if (!state.selectedScenario) return;
  try {
    await sendJson(
      `/api/evaluation/scenarios/${encodeURIComponent(state.selectedScenario.scenario_uid)}/cases`,
      "POST",
      {
        case_uid: els.caseLinkUid.value,
        relationship_status: els.caseLinkStatus.value,
        analyst_confirmed: els.caseLinkConfirmed.checked,
        notes: els.caseLinkNotes.value
      }
    );
    els.caseLinkForm.reset();
    await selectScenario(state.selectedScenario.scenario_uid);
    setStatus("ok", "Case membership saved in the Evaluation Lab.");
  } catch (error) {
    setStatus("error", error.message);
  }
}

function ratio(numerator, denominator) {
  return denominator ? numerator / denominator : null;
}

function metricValue(value) {
  return value == null ? "N/A" : `${(value * 100).toFixed(1)}%`;
}

async function loadScenarioEvents(scenario) {
  const events = [];
  for (const link of scenario.case_links || []) {
    if (!link.case_exists) continue;
    try {
      const workspace = await getJson(`/api/cases/${encodeURIComponent(link.case_uid)}`);
      for (const finding of workspace.sensor_findings || []) {
        if (!finding.event_uid) continue;
        events.push({
          event_uid: finding.event_uid,
          sensor: finding.sensor,
          case_uid: link.case_uid,
          name: finding.finding_name
        });
      }
    } catch (_error) {
      // A deleted operational case remains visible as an unavailable evaluation link.
    }
  }
  els.eventOptions.innerHTML = events.map((item) => `
    <option value="${escapeHtml(item.event_uid)}">${escapeHtml(item.sensor)} · ${escapeHtml(item.case_uid)} · ${escapeHtml(item.name || "")}</option>
  `).join("");
}

async function renderCorrelation() {
  els.correlationScenario.innerHTML = `<option value="">Select a scenario</option>` + state.scenarios.map((scenario) => `
    <option value="${escapeHtml(scenario.scenario_uid)}">${escapeHtml(scenario.scenario_uid)} · ${escapeHtml(scenario.name)}</option>
  `).join("");
  if (!state.selectedScenario && state.scenarios[0]) {
    state.selectedScenario = await getJson(`/api/evaluation/scenarios/${encodeURIComponent(state.scenarios[0].scenario_uid)}`);
  }
  if (!state.selectedScenario) {
    els.correlationMetrics.innerHTML = "";
    els.eventLabelList.innerHTML = `<div class="empty">Create a scenario before labelling event membership.</div>`;
    return;
  }
  els.correlationScenario.value = state.selectedScenario.scenario_uid;
  const labels = state.selectedScenario.event_labels || [];
  const tp = labels.filter((item) => item.label === "expected_correctly_attached").length;
  const fn = labels.filter((item) => item.label === "expected_missing").length;
  const fp = labels.filter((item) => item.label === "unexpected_incorrectly_attached").length;
  const tn = labels.filter((item) => item.label === "correctly_excluded").length;
  const precision = ratio(tp, tp + fp);
  const recall = ratio(tp, tp + fn);
  const f1 = precision == null || recall == null || precision + recall === 0
    ? null
    : (2 * precision * recall) / (precision + recall);
  els.correlationMetrics.innerHTML = [
    ["Precision", metricValue(precision), `${tp} TP · ${fp} FP`],
    ["Recall", metricValue(recall), `${tp} TP · ${fn} FN`],
    ["F1", metricValue(f1), `${labels.length} labelled events`],
    ["Correctly Excluded", tn, "True negatives"]
  ].map(([name, value, note]) => `<article class="metric"><span>${name}</span><strong>${value}</strong><small>${note}</small></article>`).join("");
  els.eventLabelList.innerHTML = `
    <table class="evaluation-table">
      <thead><tr><th>Event</th><th>Sensor</th><th>Membership</th><th>Actual case</th><th></th></tr></thead>
      <tbody>${labels.map((item) => `
        <tr>
          <td><strong>${escapeHtml(item.event_uid)}</strong><small>${escapeHtml(item.notes || "No notes")}</small></td>
          <td>${escapeHtml(label(item.event_sensor))}</td>
          <td>${escapeHtml(label(item.label))}</td>
          <td>${escapeHtml(item.actual_case_uid || "Not attached")}</td>
          <td><button class="danger-button compact-command" type="button" data-event-delete="${escapeHtml(item.event_uid)}" data-event-sensor="${escapeHtml(item.event_sensor)}">Delete</button></td>
        </tr>
      `).join("") || `<tr><td colspan="5">No event membership labels stored.</td></tr>`}</tbody>
    </table>
  `;
  await loadScenarioEvents(state.selectedScenario);
}

async function saveEventLabel(event) {
  event.preventDefault();
  if (!state.selectedScenario) {
    setStatus("warn", "Select a scenario first.");
    return;
  }
  try {
    await sendJson(
      `/api/evaluation/scenarios/${encodeURIComponent(state.selectedScenario.scenario_uid)}/events`,
      "POST",
      {
        event_uid: els.eventUid.value,
        event_sensor: els.eventSensor.value,
        actual_case_uid: els.eventCaseUid.value,
        label: els.eventLabel.value,
        notes: els.eventNotes.value
      }
    );
    els.eventLabelForm.reset();
    await selectScenario(state.selectedScenario.scenario_uid);
    setStatus("ok", "Manual event membership label saved.");
  } catch (error) {
    setStatus("error", error.message);
  }
}

function renderScoring() {
  els.scoringRunCount.textContent = state.overview?.scoring_runs || 0;
  els.scoringCases.innerHTML = state.cases.slice(0, 100).map((item) => `
    <a class="workbook-row" href="/investigation?case=${encodeURIComponent(item.case_uid)}" target="_blank" rel="noopener">
      <div class="row tight"><strong>${escapeHtml(item.case_uid)}</strong><span>${escapeHtml(item.final_score ?? "pending")}</span></div>
      <p>${escapeHtml(label(item.detection_type))} · ${escapeHtml(item.final_classification || "Pending")}</p>
      <small>${localDateTime(item.first_seen)} · ${escapeHtml(label(item.sensor_state))}</small>
    </a>
  `).join("") || `<div class="empty">No frozen cases are available.</div>`;
}

function renderModels() {
  els.modelRunCount.textContent = `${state.comparisons.length} stored run${state.comparisons.length === 1 ? "" : "s"}`;
  els.modelRunList.innerHTML = state.comparisons.map((run) => `
    <a class="workbook-row" href="/compare?run=${encodeURIComponent(run.comparison_uid)}&case=${encodeURIComponent(run.case_uid)}" target="_blank" rel="noopener">
      <div class="row tight"><strong>${escapeHtml(run.comparison_uid)}</strong><span>${escapeHtml(label(run.status))}</span></div>
      <p>${escapeHtml(run.case_uid)} · ${run.candidate_count || 0}/3 responses</p>
      <small>${localDateTime(run.created_at)} · ${run.vote_count || 0} recorded selection</small>
    </a>
  `).join("") || `<div class="empty">No three-model comparison runs are stored.</div>`;
}

async function refreshFoundation() {
  [state.overview, state.scenarios, state.cases] = await Promise.all([
    getJson("/api/evaluation/overview"),
    getJson("/api/evaluation/scenarios?limit=500"),
    getJson("/api/evaluation/cases?limit=500")
  ]);
  renderOverview();
  renderScenarioList();
  renderCaseOptions();
  renderScoring();
  if (state.view === "correlation") await renderCorrelation();
}

async function refresh() {
  try {
    await refreshFoundation();
    if (state.view === "models") {
      state.comparisons = await getJson("/api/ai-comparisons?limit=200");
      renderModels();
    }
    const requestedScenario = new URLSearchParams(location.search).get("scenario");
    if (requestedScenario && state.scenarios.some((item) => item.scenario_uid === requestedScenario)) {
      await selectScenario(requestedScenario);
    }
    els.state.textContent = "Ready";
    setStatus("ok", "Evaluation records loaded. Operational outcomes remain unchanged.");
  } catch (error) {
    els.state.textContent = "API error";
    setStatus("error", error.message);
  }
}

document.addEventListener("click", async (event) => {
  const open = event.target.closest("[data-scenario-open]");
  const edit = event.target.closest("[data-scenario-edit]");
  const unlink = event.target.closest("[data-case-unlink]");
  const deleteEvent = event.target.closest("[data-event-delete]");
  try {
    if (open) await selectScenario(open.dataset.scenarioOpen);
    if (edit) editScenario(state.scenarios.find((item) => item.scenario_uid === edit.dataset.scenarioEdit));
    if (unlink && state.selectedScenario) {
      await sendJson(
        `/api/evaluation/scenarios/${encodeURIComponent(state.selectedScenario.scenario_uid)}/cases/${encodeURIComponent(unlink.dataset.caseUnlink)}`,
        "DELETE"
      );
      await selectScenario(state.selectedScenario.scenario_uid);
    }
    if (deleteEvent && state.selectedScenario) {
      await sendJson(
        `/api/evaluation/scenarios/${encodeURIComponent(state.selectedScenario.scenario_uid)}/events/${encodeURIComponent(deleteEvent.dataset.eventSensor)}/${encodeURIComponent(deleteEvent.dataset.eventDelete)}`,
        "DELETE"
      );
      await selectScenario(state.selectedScenario.scenario_uid);
    }
  } catch (error) {
    setStatus("error", error.message);
  }
});

els.scenarioForm?.addEventListener("submit", saveScenario);
els.scenarioCancel?.addEventListener("click", resetScenarioForm);
els.scenarioRefresh?.addEventListener("click", refresh);
els.caseLinkForm?.addEventListener("submit", saveCaseLink);
els.eventLabelForm?.addEventListener("submit", saveEventLabel);
els.correlationScenario?.addEventListener("change", async () => {
  if (els.correlationScenario.value) await selectScenario(els.correlationScenario.value);
});
els.scenarioDelete?.addEventListener("click", async () => {
  if (!state.selectedScenario) return;
  const uid = state.selectedScenario.scenario_uid;
  if (!confirm(`Delete evaluation scenario ${uid} and its evaluation-only labels?`)) return;
  try {
    await sendJson(`/api/evaluation/scenarios/${encodeURIComponent(uid)}`, "DELETE");
    state.selectedScenario = null;
    els.scenarioDetailPanel.hidden = true;
    await refreshFoundation();
    setStatus("ok", `${uid} deleted. Operational cases were not changed.`);
  } catch (error) {
    setStatus("error", error.message);
  }
});

activateView();
resetScenarioForm();
refresh();

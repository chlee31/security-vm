const params = new URLSearchParams(window.location.search);
const detectionId = params.get("id");
const requestedCaseUid = params.get("case");

const els = {
  title: document.querySelector("#investigation-title"),
  updated: document.querySelector("#investigation-updated"),
  finalScore: document.querySelector("#inv-final-score"),
  decision: document.querySelector("#inv-decision"),
  action: document.querySelector("#inv-action"),
  aiConfidence: document.querySelector("#inv-ai-confidence"),
  aiClassification: document.querySelector("#inv-ai-classification"),
  sensorState: document.querySelector("#inv-sensor-state"),
  agreementState: document.querySelector("#inv-agreement-state"),
  timestamp: document.querySelector("#inv-timestamp"),
  overview: document.querySelector("#inv-overview"),
  alert: document.querySelector("#inv-alert"),
  findingCount: document.querySelector("#inv-finding-count"),
  findingViewButtons: document.querySelectorAll("[data-finding-view]"),
  ai: document.querySelector("#inv-ai"),
  scoring: document.querySelector("#inv-scoring"),
  intel: document.querySelector("#inv-intel"),
  zeek: document.querySelector("#inv-zeek"),
  reassess: document.querySelector("#inv-reassess"),
  compare: document.querySelector("#inv-compare"),
  comparison: document.querySelector("#inv-comparison"),
  refreshVt: document.querySelector("#inv-refresh-vt"),
  refresh: document.querySelector("#inv-refresh"),
  actionStatus: document.querySelector("#inv-action-status"),
  review: document.querySelector("#inv-review"),
  reviewForm: document.querySelector("#inv-review-form"),
  reviewName: document.querySelector("#inv-review-name"),
  reviewScore: document.querySelector("#inv-review-score"),
  reviewAction: document.querySelector("#inv-review-action"),
  reviewLabel: document.querySelector("#inv-review-label"),
  reviewNotes: document.querySelector("#inv-review-notes"),
  reviewStatus: document.querySelector("#inv-review-status"),
  raw: document.querySelector("#inv-raw")
};

let currentInvestigation = null;
let findingView = "unique";

function modelIdentity(candidate) {
  const provider = candidate.model_provider || "unknown provider";
  const name = candidate.model_name || candidate.model_identity || "unknown model";
  return `${provider}:${name}`;
}

const threatIntelProviders = [
  "otx", "threatfox", "urlhaus", "sslbl", "spamhaus_drop",
  "openphish", "ipsum", "feodo", "virustotal"
];

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

function renderModelCandidate(candidate, vote) {
  const selected = vote?.selection === candidate.anonymous_slot;
  return `
    <article class="model-candidate ${selected ? "winner" : ""} ${candidate.status === "failed" ? "failed" : ""}">
      <header>
        <span class="candidate-letter">${escapeHtml(candidate.anonymous_slot)}</span>
        <div>
          <strong>${escapeHtml(modelIdentity(candidate))}</strong>
          <small>profile ${escapeHtml(candidate.ai_profile_uid || "unknown")} · ${candidate.elapsed_ms ?? 0}ms</small>
        </div>
        ${selected ? `<span class="status-pill active">selected</span>` : ""}
      </header>
      ${candidate.status === "failed" ? `
        <div class="empty">Request failed: ${escapeHtml(candidate.error_message || "No error detail was stored.")}</div>
      ` : `
        <div class="candidate-verdict">
          <strong>${escapeHtml(candidate.classification || "No classification")}</strong>
          <span>${escapeHtml(candidate.confidence || "Unknown")} confidence · adjustment ${candidate.risk_adjustment ?? 0}</span>
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
        <details class="model-raw-response">
          <summary>View complete raw model response</summary>
          <pre class="raw-json">${escapeHtml(candidate.raw_response || "No raw response stored.")}</pre>
        </details>
        <footer>run ${escapeHtml(candidate.model_run_id || "not recorded")} · prompt ${escapeHtml(candidate.prompt_version || "unknown")}</footer>
      `}
    </article>
  `;
}

async function renderComparisonRuns(runs) {
  if (!runs?.length) {
    els.comparison.innerHTML = `<div class="empty comparison-empty">No three-model comparison has been run for this case.</div>`;
    return;
  }
  const latest = await getJson(`/api/ai-comparisons/${encodeURIComponent(runs[0].comparison_uid)}`);
  const vote = latest.votes?.[0];
  els.comparison.innerHTML = `
    <div class="comparison-inline-head">
      <div>
        <strong>${escapeHtml(latest.comparison_uid)}</strong>
        <small>${latest.candidate_count || 0}/3 responses · ${escapeHtml(label(latest.status))}</small>
      </div>
      <a class="nav-link" href="/compare?run=${encodeURIComponent(latest.comparison_uid)}&case=${encodeURIComponent(latest.case_uid)}" target="_blank" rel="noopener">Open Comparison Workspace</a>
    </div>
    <div class="model-candidate-grid investigation-model-grid">
      ${(latest.candidates || []).map((candidate) => renderModelCandidate(candidate, vote)).join("")}
    </div>
    ${runs.length > 1 ? `
      <details class="previous-comparison-runs">
        <summary>Previous comparison runs (${runs.length - 1})</summary>
        <div class="workbook-list">
          ${runs.slice(1).map((run) => `<a class="workbook-row investigation-link" href="/compare?run=${encodeURIComponent(run.comparison_uid)}&case=${encodeURIComponent(run.case_uid)}" target="_blank" rel="noopener"><strong>${escapeHtml(run.comparison_uid)}</strong><small>${run.candidate_count || 0}/3 responses · ${escapeHtml(label(run.status))}</small></a>`).join("")}
        </div>
      </details>
    ` : ""}
  `;
}

async function getJson(path) {
  const response = await fetch(path, { cache: "no-store" });
  if (!response.ok) throw new Error(`${path} returned ${response.status}`);
  return response.json();
}

async function sendJson(path, method, body) {
  const response = await fetch(path, {
    method,
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(formatApiError(data, `${path} returned ${response.status}`));
  return data;
}

function formatApiError(data, fallback) {
  const detail = data?.detail ?? data?.error ?? data?.message;
  if (!detail) return fallback;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) return detail.map((item) => item.msg || JSON.stringify(item)).join("; ");
  return JSON.stringify(detail);
}

function setStatus(kind, text) {
  els.reviewStatus.className = `connection-status ${kind || ""}`.trim();
  els.reviewStatus.textContent = text;
}

function setActionStatus(kind, text) {
  els.actionStatus.className = `connection-status ${kind || ""}`.trim();
  els.actionStatus.textContent = text;
}

function label(value) {
  if (!value) return "Unknown";
  return String(value).replaceAll("_", " ").replace(/\b\w/g, (char) => char.toUpperCase());
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function displayTimestamp(value) {
  if (!value) return "Unknown";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return String(value);
  return parsed.toLocaleString([], {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit"
  });
}

function row(title, body, meta = "") {
  return `
    <div class="workbook-row">
      <strong>${title}</strong>
      <p>${body || "None"}</p>
      ${meta ? `<small>${meta}</small>` : ""}
    </div>
  `;
}

function intelEndpointRow(title, profile, asset) {
  return `
    <div class="workbook-row">
      <strong>${title}</strong>
      <p>${profile?.ip_address || "unknown"} · ${profile?.location || "No local profile"} · ${profile?.scope || "unknown"}</p>
      <small>
        ${asset ? `Asset: ${asset.name} (${label(asset.device_type)}) score ${asset.asset_score}` : "No registered asset"}
      </small>
    </div>
  `;
}

function caseThreatIntelProviders(data) {
  const endpoints = [
    { label: "Source IP", value: data.src_ip, providers: data.src_threat_intel || [] },
    { label: "Destination IP", value: data.dest_ip, providers: data.dest_threat_intel || [] }
  ];
  return threatIntelProviders.map((name) => {
    const records = endpoints.flatMap((endpoint) => endpoint.providers
      .filter((provider) => provider.name === name)
      .map((provider) => ({ endpoint, provider })));
    const matches = records.filter(({ provider }) => provider.result === "matched");
    const enabled = records.some(({ provider }) => provider.enabled);
    const unavailable = enabled && records.length > 0 && records.every(({ provider }) => provider.result === "unavailable");
    const notRequested = records.some(({ provider }) => provider.result === "not_requested");
    const state = matches.length
      ? "matched"
      : unavailable
        ? "unavailable"
        : notRequested
          ? "not_requested"
          : enabled
            ? "no_match"
            : "not_active";
    const exemplar = records[0]?.provider || {};
    return {
      name,
      label: exemplar.label || label(name),
      state,
      enabled,
      indicatorCount: Math.max(0, ...records.map(({ provider }) => Number(provider.indicator_count || 0))),
      status: exemplar.status || (enabled ? "ready" : "not_active"),
      matches
    };
  });
}

function renderCaseThreatIntel(data) {
  return `
    <div class="comparison-provider-matrix case-threat-intel-grid">
      ${caseThreatIntelProviders(data).map((item) => `
        <article class="comparison-provider ${escapeHtml(item.state)}">
          <header>
            <strong>${escapeHtml(item.label)}</strong>
            <span>${escapeHtml(label(item.state))}</span>
          </header>
          <small>${item.enabled ? `${item.indicatorCount} cached indicators · ${escapeHtml(label(item.status))}` : "Provider not active"}</small>
          ${item.matches.map(({ endpoint, provider }) => `
            <p><b>${escapeHtml(endpoint.label)} ${escapeHtml(endpoint.value || "unknown")}</b>: ${(provider.matches || []).slice(0, 3).map((match) => escapeHtml(`${match.category || "indicator match"}${match.confidence != null ? ` (${match.confidence}% confidence)` : ""}${match.malware_family ? ` · ${match.malware_family}` : ""}`)).join(" · ") || `${provider.match_count || 0} provider matches`}</p>
          `).join("") || `<p>No source or destination observable matched this provider.</p>`}
        </article>
      `).join("")}
    </div>
  `;
}

function findingTimestamp(finding) {
  const parsed = new Date(finding.finding_timestamp || 0).getTime();
  return Number.isFinite(parsed) ? parsed : 0;
}

function findingGroupKey(finding) {
  return [
    finding.sensor,
    finding.finding_type,
    finding.finding_name,
    finding.source_ip,
    finding.destination_ip,
    finding.protocol
  ].map((value) => String(value || "").toLowerCase()).join("|");
}

function uniqueFindings(findings) {
  const groups = new Map();
  for (const finding of findings) {
    const key = findingGroupKey(finding);
    const existing = groups.get(key);
    if (!existing) {
      groups.set(key, {
        finding,
        count: 1,
        firstSeen: finding.finding_timestamp,
        lastSeen: finding.finding_timestamp
      });
      continue;
    }
    existing.count += 1;
    if (findingTimestamp(finding) < findingTimestamp({ finding_timestamp: existing.firstSeen })) existing.firstSeen = finding.finding_timestamp;
    if (findingTimestamp(finding) >= findingTimestamp({ finding_timestamp: existing.lastSeen })) {
      existing.lastSeen = finding.finding_timestamp;
      existing.finding = finding;
    }
  }
  return [...groups.values()].sort((left, right) => findingTimestamp(right.finding) - findingTimestamp(left.finding));
}

function findingRow(group, showEventUid) {
  const finding = group.finding;
  const countLabel = `${group.count} occurrence${group.count === 1 ? "" : "s"}`;
  const timeRange = group.count > 1
    ? `${displayTimestamp(group.firstSeen)} to ${displayTimestamp(group.lastSeen)}`
    : displayTimestamp(finding.finding_timestamp);
  return `
    <article class="finding-row">
      <header>
        <span class="sensor-badge ${escapeHtml(String(finding.sensor || "unknown").toLowerCase())}">${escapeHtml(String(finding.sensor || "unknown").toUpperCase())}</span>
        <strong>${escapeHtml(finding.finding_name || "Unnamed finding")}</strong>
        <span class="finding-count">${escapeHtml(countLabel)}</span>
      </header>
      <p>${escapeHtml(finding.source_ip || "unknown")}:${finding.source_port || ""} -&gt; ${escapeHtml(finding.destination_ip || "unknown")}:${finding.destination_port || ""} ${escapeHtml(finding.protocol || "")}</p>
      <small>${escapeHtml(timeRange)} · severity ${finding.severity ?? "unknown"} · confidence ${finding.confidence ?? "unknown"}${showEventUid ? ` · ${escapeHtml(finding.event_uid || label(finding.finding_type))}` : ""}</small>
    </article>
  `;
}

function renderSensorFindings(data) {
  const findings = [...(data.sensor_findings || [])].sort((left, right) => findingTimestamp(right) - findingTimestamp(left));
  const grouped = uniqueFindings(findings);
  const visible = findingView === "all"
    ? findings.map((finding) => ({ finding, count: 1, firstSeen: finding.finding_timestamp, lastSeen: finding.finding_timestamp }))
    : grouped;
  els.findingCount.textContent = `${grouped.length} unique · ${findings.length} total`;
  els.findingViewButtons.forEach((button) => {
    const selected = button.dataset.findingView === findingView;
    button.classList.toggle("active", selected);
    button.setAttribute("aria-pressed", String(selected));
  });
  els.alert.innerHTML = `
    <div class="finding-summary">
      ${row(
        "Fusion Summary",
        `${label(data.sensor_state || "unknown")} · ${label(data.agreement_state || "unknown")}`,
        `${label(data.correlation_method || "none")} · rule strength ${data.correlation_confidence ?? "unknown"}${data.community_id ? ` · Community ID ${escapeHtml(data.community_id)}` : ""}`
      )}
      ${row("Traffic", `${escapeHtml(data.src_ip || "unknown")}:${data.src_port || ""} -&gt; ${escapeHtml(data.dest_ip || "unknown")}:${data.dest_port || ""}`, escapeHtml(data.protocol || ""))}
    </div>
    <div class="finding-scroll-list">
      ${visible.map((group) => findingRow(group, findingView === "all")).join("") || row("Primary Finding", escapeHtml(data.signature || "No finding stored"), `${escapeHtml(data.category || "unknown category")} · priority ${data.priority || "unknown"}`)}
    </div>
  `;
}

function renderZeekContext(data) {
  const context = data.zeek_context || {};
  const items = context.items || [];
  const summary = context.summary || {};
  const byType = summary.log_counts || {};
  els.zeek.innerHTML = `
    <div class="workbook-row">
      <strong>Correlation Window</strong>
      <p>${context.window_start || "unknown"} to ${context.window_end || "unknown"}</p>
      <small>${items.length} bounded Zeek rows matched by flow, UID, endpoints, or repeated source behavior.</small>
    </div>
    <div class="workbook-row">
      <strong>Log Types</strong>
      <p>${Object.entries(byType).map(([key, value]) => `${label(key)} ${value}`).join(" · ") || "No Zeek context rows found."}</p>
      <small>Notice rows can initiate detections. Weird and protocol rows are supporting context.</small>
    </div>
    ${row("Observed Network Metadata", `DNS ${summary.dns_queries?.length || 0} · TLS names ${summary.tls_server_names?.length || 0} · HTTP hosts ${summary.http_hosts?.length || 0}`, `originator bytes ${summary.originator_bytes || 0} · responder bytes ${summary.responder_bytes || 0} · duration ${summary.connection_duration_seconds || 0}s`)}
    ${row("Repeated Activity", `${summary.case_finding_count || data.alert_count || 0} case findings over ${summary.case_window_seconds || data.time_window_seconds || 0}s`, summary.periodicity ? `${label(summary.periodicity)} intervals · average ${summary.average_interval_seconds ?? "unknown"}s` : "No reliable periodicity conclusion")}
    ${summary.dns_queries?.length ? row("DNS Queries", summary.dns_queries.map(escapeHtml).join(" · ")) : ""}
    ${summary.tls_server_names?.length ? row("TLS Server Names", summary.tls_server_names.map(escapeHtml).join(" · ")) : ""}
    ${summary.http_hosts?.length ? row("HTTP Hosts", summary.http_hosts.map(escapeHtml).join(" · ")) : ""}
    <div class="mini-list dense expanded-list">
      ${items.slice(0, 25).map((item) => `
        <div>
          <strong>${escapeHtml(item.event_uid || item.event_name || item.log_type || "Zeek event")}</strong>
          <small>${escapeHtml(item.message || "No message")} · ${escapeHtml(item.timestamp || "")}</small>
          <small>${escapeHtml(item.source_ip || "unknown")}:${item.source_port || ""} -> ${escapeHtml(item.destination_ip || "unknown")}:${item.destination_port || ""} ${escapeHtml(item.protocol || "")}</small>
        </div>
      `).join("") || `<div class="empty">No Zeek context was found for this detection yet.</div>`}
    </div>
  `;
}

function render(data) {
  currentInvestigation = data;
  els.title.textContent = data.case_uid || `${label(data.detection_type)} #${data.detection_id}`;
  if (data.case_uid && !requestedCaseUid) {
    history.replaceState(null, "", `/investigation?case=${encodeURIComponent(data.case_uid)}`);
  }
  els.finalScore.textContent = data.final_score ?? data.python_initial_score ?? 0;
  els.decision.textContent = data.final_classification || "No decision";
  els.action.textContent = data.final_action || "No action";
  els.aiConfidence.textContent = data.ai_confidence || "None";
  els.aiClassification.textContent = data.ai_classification || "No AI opinion";
  els.sensorState.textContent = label(data.sensor_state || "unknown");
  els.agreementState.textContent = `${label(data.agreement_state || "unknown")} · ${label(data.correlation_method || "none")}`;
  els.timestamp.textContent = displayTimestamp(data.timestamp || data.first_seen);

  const nextSteps = Array.isArray(data.ai_next_steps) ? data.ai_next_steps : [];
  els.overview.innerHTML = [
    row("Summary", escapeHtml(data.ai_summary || data.ai_reason || "No AI case summary stored yet.")),
    row("Who", escapeHtml(data.ai_who || `${data.src_ip || "Unknown source"} and ${data.dest_ip || "unknown destination"}`)),
    row("What", escapeHtml(data.ai_what || data.signature || "Network sensor activity")),
    row("When", escapeHtml(data.ai_when || `${displayTimestamp(data.first_seen)} to ${displayTimestamp(data.last_seen)}`)),
    row("Where", escapeHtml(data.ai_where || `${data.src_ip || "?"}:${data.src_port || "?"} to ${data.dest_ip || "?"}:${data.dest_port || "?"}`)),
    row("Why", escapeHtml(data.ai_why || data.ai_reason || "Review the sensor evidence and deterministic score.")),
    row("How", escapeHtml(data.ai_how || `Correlated using ${label(data.correlation_method || "single_sensor")}.`)),
    row("Next Steps", nextSteps.length ? nextSteps.map(escapeHtml).join(" · ") : escapeHtml(data.ai_recommended_action || "Review the evidence and record an analyst decision."))
  ].join("");

  renderSensorFindings(data);

  const assessments = data.ai_assessments || [];
  const selectedIntelAnalysis = data.ai_threat_intel_analysis || {};
  els.ai.innerHTML = [
    row("Classification", data.ai_classification || "No AI opinion", `${data.ai_confidence || "No"} confidence`),
    row("AI Profile UID", data.ai_profile_uid || "legacy-profile", "Selected Admin profile stamped into this report"),
    row("Model Identity", data.ai_model_identity || "unknown model", `provider ${data.ai_model_provider || "unknown"} · name ${data.ai_model_name || "unknown"}`),
    row("Model Run", data.ai_model_run_id || "not recorded", `${data.ai_prompt_version || "unknown prompt"} · ${data.ai_elapsed_ms ?? 0}ms`),
    row("Reason", data.ai_reason || "No AI reason stored."),
    row(
      "Threat Intelligence Conclusion",
      selectedIntelAnalysis.overall || "No dedicated threat-intelligence conclusion stored for this response.",
      `Influence: ${label(selectedIntelAnalysis.influence || "unavailable")}`
    ),
    row("Evidence Boundaries", "Network metadata only", "No raw packet capture, decrypted payload, endpoint telemetry, or user identity was supplied to the model."),
    row("Recommended Action", data.ai_recommended_action || "none", `Risk adjustment ${data.ai_risk_adjustment ?? 0}`),
    ...assessments.map((item) => row(
      `${label(item.assessment_type)} · ${item.model_name || "unknown model"}`,
      `${item.classification || "Unknown"} · adjustment ${item.risk_adjustment ?? 0}`,
      `${item.confidence || "Unknown"} confidence · ${displayTimestamp(item.created_at)}`
    )),
  ].join("");

  const breakdowns = data.score_breakdowns || [];
  const latestBreakdown = breakdowns.at(-1);
  const categoryLabels = {
    sensor_severity: "Sensor finding severity",
    behavior_correlation: "Behavior and time correlation",
    threat_intelligence: "Cached and bulk threat intelligence",
    mitre_relevance: "MITRE ATT&CK relevance",
    asset_direction: "Registered IP importance and direction",
    sensor_corroboration: "Suricata-Zeek corroboration"
  };
  const categoryMax = {
    sensor_severity: 20,
    behavior_correlation: 20,
    threat_intelligence: 20,
    mitre_relevance: 10,
    asset_direction: 10,
    sensor_corroboration: 10
  };
  els.scoring.innerHTML = [
    row("Python Deterministic Score", latestBreakdown?.python_score ?? data.python_initial_score ?? 0, "Maximum 90 points"),
    ...Object.entries(categoryLabels).map(([key, title]) => row(
      title,
      `${latestBreakdown?.[key] ?? 0} / ${categoryMax[key]}`,
      latestBreakdown?.details?.[key]?.explanation || "No stored category explanation for this legacy decision."
    )),
    row("AI Adjustment", latestBreakdown?.llm_adjustment_applied ?? data.ai_risk_adjustment ?? 0, "Independently clamped from -10 to +10"),
    latestBreakdown?.forced_review ? row("Mandatory Review Override", "Human Review Required", latestBreakdown.forced_review_reason || "Materially disputed sensor findings") : "",
    row("Correlation", `${data.alert_count || 0} sensor events · ${data.unique_dest_ports || 0} destination ports · ${data.unique_dest_hosts || 0} hosts`, `${data.time_window_seconds || 0}s window · ${label(data.correlation_method || "single_sensor")}`),
    row("MITRE", data.mitre_id ? `${data.mitre_id} · ${data.mitre_name || ""}` : "No MITRE mapping"),
  ].filter(Boolean).join("");

  const vtRows = data.virustotal_verifications || [];
  els.intel.innerHTML = [
    intelEndpointRow("Source IP", data.src_ip_profile, data.src_asset),
    intelEndpointRow("Destination IP", data.dest_ip_profile, data.dest_asset),
    renderCaseThreatIntel(data),
    row(
      "VirusTotal Verification",
      vtRows.length ? `${vtRows.length} stored verification record${vtRows.length === 1 ? "" : "s"}` : "Not requested",
      "Post-AI evidence only. VirusTotal never changes the numerical score."
    ),
    ...vtRows.map((item) => row(
      `${item.ip_address || "No eligible public IP"} · ${label(item.request_state)}`,
      `${label(item.verdict)} · ${label(item.interpretation)}`,
      `malicious ${item.malicious_count || 0} · suspicious ${item.suspicious_count || 0} · ${displayTimestamp(item.checked_at)}`
    )),
  ].join("");

  els.review.innerHTML = [
    row("Review Status", data.review_status || "No review item", data.due_at ? `Due ${data.due_at}` : ""),
    row("Analyst Action", data.analyst_action || "No analyst override", data.analyst_name ? `by ${data.analyst_name}` : ""),
    row("Analyst Notes", data.analyst_notes || "No notes"),
  ].join("");
  els.reviewName.value = data.analyst_name || "";
  els.reviewScore.value = data.analyst_score ?? "";
  els.reviewNotes.value = data.analyst_notes || "";
  setStatus("", data.review_status ? `Current review status: ${data.review_status}` : "No review item stored yet.");

  els.raw.innerHTML = `
    <div class="workbook-row">
      <strong>Raw AI Response</strong>
      <pre class="raw-json">${escapeHtml(data.ai_raw_response || "No raw AI response stored.")}</pre>
    </div>
  `;

  renderZeekContext(data);
  els.updated.textContent = new Date().toLocaleTimeString();
}

function classificationForAction(action) {
  if (action === "log_only") return "Safe";
  if (action === "escalate") return "Dangerous";
  if (action === "investigate") return "High Risk";
  return "Human Review Required";
}

async function submitReview(event) {
  event.preventDefault();
  if (!currentInvestigation?.detection_id) return;
  const action = els.reviewAction.value;
  const scoreValue = els.reviewScore.value;
  try {
    await sendJson(`/api/reviews/${currentInvestigation.detection_id}`, "POST", {
      action,
      analyst_name: els.reviewName.value,
      notes: els.reviewNotes.value,
      tuning_label: els.reviewLabel.value,
      score: action === "confirm" || scoreValue === "" ? null : Number(scoreValue),
      classification: classificationForAction(action)
    });
    await refresh();
    setStatus("ok", "Review saved.");
  } catch (error) {
    setStatus("error", error.message);
  }
}

async function reassess() {
  if (!currentInvestigation?.case_uid) return;
  els.reassess.disabled = true;
  setActionStatus("", "Reassessment in progress. One AI request will be made.");
  try {
    const result = await sendJson(`/api/cases/${encodeURIComponent(currentInvestigation.case_uid)}/reassess`, "POST");
    await refresh();
    setActionStatus("ok", `Reassessment stored: ${result.response?.final_classification || "complete"}.`);
  } catch (error) {
    setActionStatus("error", error.message);
  } finally {
    els.reassess.disabled = false;
  }
}

async function runComparison() {
  if (!currentInvestigation?.case_uid) return;
  els.compare.disabled = true;
  setActionStatus("", "Running three AI requests sequentially. This can take several minutes; keep this page open.");
  try {
    const result = await sendJson(`/api/cases/${encodeURIComponent(currentInvestigation.case_uid)}/ai-comparison`, "POST");
    await refresh();
    setActionStatus("ok", `${result.candidate_count || 0}/3 model responses completed and are displayed below.`);
  } catch (error) {
    setActionStatus("error", error.message);
  } finally {
    els.compare.disabled = false;
  }
}

async function refreshVirusTotal() {
  if (!currentInvestigation?.case_uid) return;
  els.refreshVt.disabled = true;
  setActionStatus("", "Refreshing eligible public IPs with VirusTotal.");
  try {
    await sendJson(`/api/cases/${encodeURIComponent(currentInvestigation.case_uid)}/virustotal/refresh`, "POST");
    await refresh();
    setActionStatus("ok", "VirusTotal refreshed. Reassess explicitly if another AI opinion is needed.");
  } catch (error) {
    setActionStatus("error", error.message);
  } finally {
    els.refreshVt.disabled = false;
  }
}

async function refresh() {
  if (!detectionId && !requestedCaseUid && !currentInvestigation?.case_uid) {
    els.updated.textContent = "Missing detection id";
    els.alert.innerHTML = `<div class="empty">Open this page from an alert, AI opinion, evidence row, or review item.</div>`;
    return;
  }
  try {
    const caseUid = requestedCaseUid || currentInvestigation?.case_uid;
    const path = caseUid
      ? `/api/cases/${encodeURIComponent(caseUid)}`
      : `/api/investigation/${encodeURIComponent(detectionId)}`;
    const data = await getJson(path);
    render(data);
    if (data.case_uid) {
      await renderComparisonRuns(await getJson(`/api/cases/${encodeURIComponent(data.case_uid)}/ai-comparisons?limit=10`));
    } else {
      await renderComparisonRuns([]);
    }
  } catch (error) {
    els.updated.textContent = "Investigation API error";
    els.alert.innerHTML = `<div class="empty">${error.message}</div>`;
  }
}

refresh();
els.reviewForm.addEventListener("submit", submitReview);
els.reassess.addEventListener("click", reassess);
els.compare.addEventListener("click", runComparison);
els.refreshVt.addEventListener("click", refreshVirusTotal);
els.refresh.addEventListener("click", refresh);
els.findingViewButtons.forEach((button) => button.addEventListener("click", () => {
  findingView = button.dataset.findingView === "all" ? "all" : "unique";
  if (currentInvestigation) renderSensorFindings(currentInvestigation);
}));

const params = new URLSearchParams(window.location.search);
const detectionId = params.get("id");
const requestedCaseUid = params.get("case");

const els = {
  title: document.querySelector("#investigation-title"),
  updated: document.querySelector("#investigation-updated"),
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
  intel: document.querySelector("#inv-intel"),
  zeek: document.querySelector("#inv-zeek"),
  audit: document.querySelector("#inv-audit"),
  reassess: document.querySelector("#inv-reassess"),
  compare: document.querySelector("#inv-compare"),
  comparison: document.querySelector("#inv-comparison"),
  refreshVt: document.querySelector("#inv-refresh-vt"),
  refresh: document.querySelector("#inv-refresh"),
  actionStatus: document.querySelector("#inv-action-status"),
  review: document.querySelector("#inv-review"),
  reviewForm: document.querySelector("#inv-review-form"),
  reviewName: document.querySelector("#inv-review-name"),
  reviewAction: document.querySelector("#inv-review-action"),
  reviewLabel: document.querySelector("#inv-review-label"),
  reviewNotes: document.querySelector("#inv-review-notes"),
  reviewStatus: document.querySelector("#inv-review-status")
};

let currentInvestigation = null;
let findingView = "all";

function modelIdentity(candidate) {
  const provider = candidate.model_provider || "unknown provider";
  const name = candidate.model_name || candidate.model_identity || "unknown model";
  return `${provider}:${name}`;
}

function selectedModelIdentity(data) {
  return modelIdentity({
    model_provider: data.ai_model_provider,
    model_name: data.ai_model_name,
    model_identity: data.ai_model_identity
  });
}

function sourceHeading(source, title, detail = "") {
  return `
    <span class="content-source ${source.toLowerCase()}">${escapeHtml(source)}</span>
    ${escapeHtml(title)}
    ${detail ? `<small class="content-source-detail">${escapeHtml(detail)}</small>` : ""}
  `;
}

function orderedSteps(steps, fallback) {
  const items = Array.isArray(steps)
    ? steps.map((step) => String(step || "").trim()).filter(Boolean)
    : [];
  if (!items.length && fallback) items.push(String(fallback));
  return `
    <ol class="recommended-step-list">
      ${items.map((step) => `<li>${escapeHtml(step)}</li>`).join("") || "<li>No recommendation was returned.</li>"}
    </ol>
  `;
}

function endpointIdentity(ip) {
  return ip || "Unknown endpoint";
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
          <strong>Response ${escapeHtml(candidate.anonymous_slot)}</strong>
          <small>${candidate.status === "failed" ? "Request failed" : `${candidate.elapsed_ms ?? 0}ms`}</small>
        </div>
        ${selected ? `<span class="status-pill active">selected</span>` : ""}
      </header>
      ${candidate.status === "failed" ? `
        <div class="empty">Request failed: ${escapeHtml(candidate.error_message || "No error detail was stored.")}</div>
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
        <details class="model-raw-response">
          <summary>View complete raw model response</summary>
          <pre class="raw-json">${escapeHtml(candidate.raw_response || "No raw response stored.")}</pre>
        </details>
        <footer>Response ${escapeHtml(candidate.anonymous_slot)} · prompt ${escapeHtml(candidate.prompt_version || "unknown")}</footer>
      `}
    </article>
  `;
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
          ? "The comparison reuses the exact prompt and evidence snapshot that produced the initial case summary."
          : "This comparison used a separately prepared case snapshot; differences from the initial summary may reflect changed evidence as well as model behavior."}</small>
      </div>
      <details>
        <summary>View input hashes</summary>
        <p>Prompt SHA-256: <span class="hash-value">${escapeHtml(proof.prompt_sha256 || "not recorded")}</span></p>
        <p>Evidence SHA-256: <span class="hash-value">${escapeHtml(proof.evidence_sha256 || "not recorded")}</span></p>
      </details>
    </section>
  `;
}

async function renderComparisonRuns(runs) {
  if (!runs?.length) {
    els.comparison.innerHTML = `<div class="empty comparison-empty">No model comparison has been run for this case.</div>`;
    return;
  }
  const latest = await getJson(`/api/ai-comparisons/${encodeURIComponent(runs[0].comparison_uid)}`);
  const vote = latest.votes?.[0];
  const expected = latest.expected_candidate_count || latest.selected_profile_uids?.length || 0;
  els.comparison.innerHTML = `
    <div class="comparison-inline-head">
      <div>
        <strong>${escapeHtml(latest.comparison_uid)}</strong>
        <small>${latest.candidate_count || 0}/${expected} successful · ${latest.processed_count || 0}/${expected} attempted · ${escapeHtml(label(latest.status))}</small>
      </div>
      <a class="nav-link" href="/compare?run=${encodeURIComponent(latest.comparison_uid)}&case=${encodeURIComponent(latest.case_uid)}" target="_blank" rel="noopener">Open Comparison Workspace</a>
    </div>
    ${renderComparisonInputProof(latest)}
    <div class="model-candidate-grid investigation-model-grid">
      ${(latest.candidates || []).map((candidate) => renderModelCandidate(candidate, vote)).join("")}
    </div>
    ${runs.length > 1 ? `
      <details class="previous-comparison-runs">
        <summary>Previous comparison runs (${runs.length - 1})</summary>
        <div class="workbook-list">
          ${runs.slice(1).map((run) => {
            const runExpected = run.expected_candidate_count || 0;
            return `<a class="workbook-row investigation-link" href="/compare?run=${encodeURIComponent(run.comparison_uid)}&case=${encodeURIComponent(run.case_uid)}" target="_blank" rel="noopener"><strong>${escapeHtml(run.comparison_uid)}</strong><small>${run.candidate_count || 0}/${runExpected} successful · ${run.processed_count || 0}/${runExpected} attempted · ${escapeHtml(label(run.status))}</small></a>`;
          }).join("")}
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

function row(title, body, meta = "", className = "") {
  return `
    <div class="workbook-row${className ? ` ${escapeHtml(className)}` : ""}">
      <strong>${title}</strong>
      <p>${body || "None"}</p>
      ${meta ? `<small>${meta}</small>` : ""}
    </div>
  `;
}

function intelEndpointRow(title, profile) {
  return `
    <div class="workbook-row">
      <strong>${title}</strong>
      <p>${profile?.ip_address || "unknown"} · ${profile?.location || "No local profile"} · ${profile?.scope || "unknown"}</p>
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

function renderZeekThreatIntel(data) {
  const evidence = data.zeek_threat_intel || {};
  const items = evidence.items || [];
  const providers = evidence.active_providers || [];
  return `
    <div class="workbook-row">
      <strong>Zeek-Derived Observables</strong>
      <p>${evidence.unique_count || 0} unique indicators checked · ${evidence.included_count || 0} shown · ${evidence.matched_count || 0} matched</p>
      <small>${providers.length ? `Cached providers: ${providers.map(label).join(" · ")}` : "No pre-AI threat-intelligence providers are active."}${evidence.omitted_count ? ` · ${evidence.omitted_count} lower-priority indicators omitted by the evidence limit` : ""}</small>
    </div>
    <div class="mini-list dense expanded-list">
      ${items.map((item) => {
        const matches = item.matches || [];
        const first = (item.provenance || [])[0] || {};
        const matchText = matches.length
          ? matches.map((match) => `${label(match.source)}: ${match.category || match.reputation || "indicator match"}${match.confidence != null ? ` (${match.confidence}% confidence)` : ""}`).join(" · ")
          : "No active cached provider match";
        return `
          <div>
            <strong>${escapeHtml(item.indicator || "unknown")} <span class="muted">${escapeHtml(label(item.indicator_type))}</span></strong>
            <small>Zeek logs: ${escapeHtml((item.log_types || []).map(label).join(" · ") || "Unknown")} · ${item.occurrences || 0} occurrence${item.occurrences === 1 ? "" : "s"}</small>
            <small>Associated IPs: ${escapeHtml((item.associated_ips || []).join(" · ") || "none stored")}</small>
            <small>${escapeHtml(matchText)}</small>
            ${first.timestamp ? `<small>First included record: ${escapeHtml(displayTimestamp(first.timestamp))} · field ${escapeHtml(first.field || "unknown")}${first.zeek_uid ? ` · UID ${escapeHtml(first.zeek_uid)}` : ""}</small>` : ""}
          </div>
        `;
      }).join("") || `<div class="empty">No IOC-like values were extracted from the bounded Zeek context for this case.</div>`}
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
      <dl class="sensor-provenance-grid">
        <div><dt>Source record</dt><dd>${escapeHtml(finding.source_table || "unknown")}[${finding.source_record_id ?? finding.sensor_event_id ?? "?"}]</dd></div>
        <div><dt>Event UID</dt><dd>${escapeHtml(finding.event_uid || "not recorded")}</dd></div>
        <div><dt>Source endpoint</dt><dd>${escapeHtml(finding.source_ip || "unknown")}:${finding.source_port ?? "?"}</dd></div>
        <div><dt>Destination endpoint</dt><dd>${escapeHtml(finding.destination_ip || "unknown")}:${finding.destination_port ?? "?"}</dd></div>
        <div><dt>Protocol</dt><dd>${escapeHtml(finding.protocol || "unknown")}</dd></div>
        <div><dt>Raw SHA-256</dt><dd class="hash-value">${escapeHtml(finding.raw_record_sha256 || "not recorded")}</dd></div>
      </dl>
      <details class="sensor-raw-record">
        <summary>View raw ${escapeHtml(label(finding.sensor || "sensor"))} record and field lineage</summary>
        <h4>Field lineage</h4>
        <pre class="raw-json">${escapeHtml(JSON.stringify(finding.field_provenance || {}, null, 2))}</pre>
        <h4>Raw sensor JSON</h4>
        <pre class="raw-json">${escapeHtml(JSON.stringify(finding.raw_record || {}, null, 2))}</pre>
      </details>
    </article>
  `;
}

function renderSensorFindings(data) {
  const findings = [...(data.sensor_findings || [])].sort((left, right) => findingTimestamp(right) - findingTimestamp(left));
  const grouped = uniqueFindings(findings);
  const visibleGroups = findingView === "all"
    ? findings.map((finding) => ({ finding, count: 1, firstSeen: finding.finding_timestamp, lastSeen: finding.finding_timestamp }))
    : grouped;
  const suricataGroups = visibleGroups.filter((group) => String(group.finding.sensor || "").toLowerCase() === "suricata");
  const zeekGroups = visibleGroups.filter((group) => String(group.finding.sensor || "").toLowerCase() === "zeek");
  const suricataCount = findings.filter((finding) => String(finding.sensor || "").toLowerCase() === "suricata").length;
  const zeekCount = findings.filter((finding) => String(finding.sensor || "").toLowerCase() === "zeek").length;
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
      ${row(
        "Correlation Proof",
        `${findings.length} stored sensor record${findings.length === 1 ? "" : "s"} connected to ${escapeHtml(data.case_uid || `detection ${data.detection_id}`)}`,
        data.community_id
          ? `Python joined compatible records using Community ID ${escapeHtml(data.community_id)} and validated flow/time context.`
          : `Python used ${escapeHtml(label(data.correlation_method || "single_sensor"))}; no shared Community ID was stored for this case.`
      )}
      ${row("Traffic", `${escapeHtml(data.src_ip || "unknown")}:${data.src_port || ""} -&gt; ${escapeHtml(data.dest_ip || "unknown")}:${data.dest_port || ""}`, escapeHtml(data.protocol || ""))}
    </div>
    <div class="sensor-log-columns">
      <section class="sensor-log-panel suricata-log-panel">
        <header>
          <div>
            <span class="sensor-badge suricata">SURICATA</span>
            <h3>Suricata Logs</h3>
          </div>
          <span>${suricataCount} event${suricataCount === 1 ? "" : "s"}</span>
        </header>
        <div class="sensor-log-scroll">
          ${suricataGroups.map((group) => findingRow(group, findingView === "all")).join("") || `<div class="empty">No Suricata finding is attached to this case.</div>`}
        </div>
      </section>
      <section class="sensor-log-panel zeek-log-panel">
        <header>
          <div>
            <span class="sensor-badge zeek">ZEEK</span>
            <h3>Zeek Logs</h3>
          </div>
          <span>${zeekCount} event${zeekCount === 1 ? "" : "s"}</span>
        </header>
        <div class="sensor-log-scroll">
          ${zeekGroups.map((group) => findingRow(group, findingView === "all")).join("") || `<div class="empty">No Zeek finding is attached to this case. Supporting Zeek protocol rows may still appear under Related Network Context.</div>`}
        </div>
      </section>
    </div>
  `;
}

function renderAiAudit(data) {
  const audits = data.ai_run_audits || [];
  if (!audits.length) {
    els.audit.innerHTML = `<div class="empty">No full request audit exists for this legacy case. New model requests are recorded automatically.</div>`;
    return;
  }
  els.audit.innerHTML = audits.map((audit, index) => {
    const manifest = audit.evidence_manifest || {};
    const omissions = audit.omission_manifest || [];
    const request = audit.request_options || {};
    const responseMetrics = audit.response_metrics || {};
    const review = audit.model_evidence_review || (index === 0 ? (data.ai_evidence_review || {}) : {});
    const response = audit.model_response || {};
    const auditModel = modelIdentity({
      model_provider: audit.model_provider,
      model_name: audit.model_name
    });
    return `
      <article class="ai-audit-record">
        <header>
          <div>
            <strong>${escapeHtml(label(audit.assessment_type || "model request"))}</strong>
            <small>${escapeHtml(audit.model_provider || "unknown")}:${escapeHtml(audit.model_name || "unknown")} · ${escapeHtml(audit.model_run_id || "no run ID")}</small>
          </div>
          <span class="status-pill ${audit.status === "complete" ? "active" : ""}">${escapeHtml(label(audit.status || "unknown"))}</span>
        </header>
        <dl class="audit-metrics">
          <div><dt>Prompt</dt><dd>${audit.prompt_chars ?? 0} chars · ${audit.prompt_bytes ?? 0} bytes</dd></div>
          <div><dt>Evidence JSON</dt><dd>${audit.evidence_chars ?? 0} chars · ${audit.evidence_bytes ?? 0} bytes</dd></div>
          <div><dt>Context fit</dt><dd>${request.estimated_prompt_tokens ?? "?"} estimated tokens · ${request.estimated_fits_configured_context === false ? "OVER CONFIGURED INPUT BUDGET" : "within estimate"}</dd></div>
          <div><dt>Model measured input</dt><dd>${responseMetrics.prompt_eval_count ?? "not returned"} tokens</dd></div>
          <div><dt>Included records</dt><dd>${manifest.sensor_finding_count ?? 0} findings · ${manifest.zeek_context_count ?? 0} Zeek rows</dd></div>
          <div><dt>Omissions</dt><dd>${omissions.length} recorded</dd></div>
          <div><dt>Parse result</dt><dd>${escapeHtml(label(audit.parse_status || "not returned"))}</dd></div>
          <div><dt>Prompt SHA-256</dt><dd class="hash-value">${escapeHtml(audit.prompt_sha256 || "not recorded")}</dd></div>
          <div><dt>Evidence SHA-256</dt><dd class="hash-value">${escapeHtml(audit.evidence_sha256 || "not recorded")}</dd></div>
          <div><dt>Response SHA-256</dt><dd class="hash-value">${escapeHtml(audit.response_sha256 || "not returned")}</dd></div>
        </dl>
        ${audit.parse_error ? `<div class="connection-status error">${escapeHtml(audit.parse_error)}</div>` : ""}
        <details>
          <summary>Exact prompt sent to the model</summary>
          <pre class="raw-json audit-document">${escapeHtml(audit.prompt_text || "No prompt stored.")}</pre>
        </details>
        <details>
          <summary>Exact normalized evidence package</summary>
          <pre class="raw-json audit-document">${escapeHtml(JSON.stringify(audit.evidence_package || {}, null, 2))}</pre>
        </details>
        <details>
          <summary>Source map and correlation lineage</summary>
          <pre class="raw-json audit-document">${escapeHtml(JSON.stringify(audit.source_map || {}, null, 2))}</pre>
        </details>
        <details>
          <summary>Python omission and truncation manifest (${omissions.length})</summary>
          <pre class="raw-json audit-document">${escapeHtml(JSON.stringify(omissions, null, 2))}</pre>
        </details>
        <details>
          <summary>Request settings and structured-output contract</summary>
          <pre class="raw-json audit-document">${escapeHtml(JSON.stringify(audit.request_options || {}, null, 2))}</pre>
        </details>
        ${Object.keys(review).length ? `
          <section class="model-evidence-acknowledgement">
            <h3>Model Evidence Acknowledgement</h3>
            <p><strong>Review method:</strong> ${escapeHtml(review.review_method || "Legacy response did not acknowledge its evidence review.")}</p>
            <p><strong>Sections received:</strong> ${escapeHtml((review.received_sections || []).join(" · ") || "Not reported")}</p>
            <p><strong>Evidence cited:</strong> ${escapeHtml((review.evidence_used || []).join(" · ") || "Not reported")}</p>
            <p><strong>Missing or ambiguous:</strong> ${escapeHtml((review.missing_or_ambiguous || []).join(" · ") || "None reported")}</p>
            <small>This acknowledgement is explanatory. The Python-captured prompt, package, and hashes above are the authoritative proof.</small>
          </section>
        ` : ""}
        ${Object.keys(response).length ? `
          <section class="audited-model-response">
            <header>
              <div>
                <span class="content-source ai">AI</span>
                <h3>Stored Model Reply</h3>
                <small>${escapeHtml(auditModel)} · run ${escapeHtml(audit.model_run_id || "not recorded")}</small>
              </div>
              <span class="status-pill">${escapeHtml(response.confidence || "Unknown")} confidence</span>
            </header>
            <div class="audited-response-verdict">
              <strong>${escapeHtml(response.classification || "No classification returned")}</strong>
              <span>${escapeHtml(response.recommended_action || "No action returned")}</span>
            </div>
            <div class="audited-response-grid">
              <section>
                <h4>AI Summary</h4>
                <p>${escapeHtml(response.summary || "No summary returned.")}</p>
              </section>
              <section>
                <h4>AI Reasoning</h4>
                <p>${escapeHtml(response.reason || "No reason returned.")}</p>
              </section>
              <section><h4>Who</h4><p>${escapeHtml(response.who || "Not established")}</p></section>
              <section><h4>What</h4><p>${escapeHtml(response.what || "Not established")}</p></section>
              <section><h4>When</h4><p>${escapeHtml(response.when || "Not established")}</p></section>
              <section><h4>Where</h4><p>${escapeHtml(response.where || "Not established")}</p></section>
              <section><h4>Why</h4><p>${escapeHtml(response.why || "Not established")}</p></section>
              <section><h4>How</h4><p>${escapeHtml(response.how || "Not established")}</p></section>
            </div>
            <section class="audited-response-steps">
              <h4>AI Recommended Next Steps</h4>
              ${orderedSteps(response.next_steps, response.recommended_action)}
            </section>
            <details>
              <summary>Complete raw reply from this model run</summary>
              <pre class="raw-json audit-document">${escapeHtml(audit.response_text || "No raw response stored.")}</pre>
            </details>
          </section>
        ` : `
          <div class="connection-status">The raw response is stored, but no normalized model reply could be displayed.</div>
        `}
      </article>
    `;
  }).join("");
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
          <strong>${escapeHtml(label(item.log_type || "unknown"))} log · ${escapeHtml(item.zeek_uid || item.event_name || `event ${item.id || "unknown"}`)}</strong>
          <small>${escapeHtml(item.message || "No message")} · ${escapeHtml(item.timestamp || "")}</small>
          <small>${escapeHtml(item.source_ip || "unknown")}:${item.source_port || ""} -> ${escapeHtml(item.destination_ip || "unknown")}:${item.destination_port || ""} ${escapeHtml(item.protocol || "")}</small>
          ${Object.keys(item.details || {}).length ? `<small>${escapeHtml(Object.entries(item.details).map(([key, value]) => `${label(key)}: ${Array.isArray(value) ? value.join(", ") : value}`).join(" · "))}</small>` : ""}
        </div>
      `).join("") || `<div class="empty">No Zeek context was found for this detection yet.</div>`}
    </div>
  `;
}

function render(data) {
  currentInvestigation = data;
  const promoted = data.selected_ai_explanation || null;
  const hasAiReport = Boolean(data.ai_report_available || promoted);
  const hasDecision = Boolean(data.decision_available);
  els.title.textContent = data.case_uid || `${label(data.detection_type)} #${data.detection_id}`;
  if (data.case_uid && !requestedCaseUid) {
    history.replaceState(null, "", `/investigation?case=${encodeURIComponent(data.case_uid)}`);
  }
  els.decision.textContent = hasDecision ? (data.final_classification || "—") : "—";
  els.action.textContent = hasDecision ? (data.final_action || "—") : "";
  els.aiConfidence.textContent = hasAiReport
    ? (promoted?.confidence || data.ai_confidence || "—")
    : "—";
  els.aiClassification.textContent = hasAiReport
    ? (promoted?.classification || data.ai_classification || "—")
    : "";
  els.sensorState.textContent = label(data.sensor_state || "unknown");
  els.agreementState.textContent = `${label(data.agreement_state || "unknown")} · ${label(data.correlation_method || "none")}`;
  els.timestamp.textContent = displayTimestamp(data.timestamp || data.first_seen);

  const nextSteps = promoted
    ? (Array.isArray(promoted.next_steps) ? promoted.next_steps : [])
    : (Array.isArray(data.ai_next_steps) ? data.ai_next_steps : []);
  const aiModel = hasAiReport
    ? promoted
      ? modelIdentity(promoted)
      : selectedModelIdentity(data)
    : "";
  const aiRun = hasAiReport
    ? (promoted?.model_run_id || data.ai_model_run_id || "not recorded")
    : "";
  const explanationSource = promoted
    ? `${aiModel} · analyst-selected Response ${promoted.anonymous_slot}`
    : aiModel;
  const aiSummary = promoted?.summary || data.ai_summary || data.ai_reason;
  const aiWhy = promoted?.why_summary || promoted?.summary || data.ai_why || data.ai_reason;
  const aiAction = promoted?.recommended_action || data.ai_recommended_action;
  const aiRawResponse = promoted?.raw_response || data.ai_raw_response;
  const sensors = [...new Set(
    (data.sensor_findings || [])
      .map((finding) => label(finding.sensor))
      .filter((sensor) => sensor && sensor !== "Unknown")
  )];
  const sensorText = sensors.length ? sensors.join(" and ") : label(data.sensor_state || "unknown sensor");
  const pythonWho = [
    `Source: ${endpointIdentity(data.src_ip)}`,
    `Destination: ${endpointIdentity(data.dest_ip)}`
  ].join(" · ");
  const pythonWhat = `${data.signature || label(data.detection_type) || "Network sensor activity"} · observed by ${sensorText}`;
  const pythonWhen = `${displayTimestamp(data.first_seen || data.timestamp)} to ${displayTimestamp(data.last_seen || data.timestamp)}`;
  const pythonWhere = `${data.src_ip || "unknown"}:${data.src_port ?? "unknown"} to ${data.dest_ip || "unknown"}:${data.dest_port ?? "unknown"} ${data.protocol || ""}`.trim();
  const pythonHow = `${sensorText} records joined using ${label(data.correlation_method || "single_sensor")}; ${data.sensor_findings?.length || 0} stored finding${data.sensor_findings?.length === 1 ? "" : "s"}.`;
  const aiOverview = hasAiReport ? [
    row(
      sourceHeading("AI", "Summary", explanationSource),
      escapeHtml(aiSummary || "No summary was returned."),
      `Model run ${escapeHtml(aiRun)}`
    ),
    row(
      sourceHeading("AI", "Why It May Matter", explanationSource),
      escapeHtml(aiWhy || "No interpretation was returned."),
      `Model run ${escapeHtml(aiRun)}`
    ),
    row(
      sourceHeading("AI", "Recommended Next Steps", explanationSource),
      orderedSteps(nextSteps, aiAction),
      `Model run ${escapeHtml(aiRun)}`,
      "overview-recommendations"
    ),
    `
      <details class="summary-raw-response">
        <summary>View raw AI response from ${escapeHtml(explanationSource)}</summary>
        <pre class="raw-json">${escapeHtml(aiRawResponse || "No raw AI response stored.")}</pre>
      </details>
    `
  ] : [];
  els.overview.innerHTML = [
    ...aiOverview.slice(0, 1),
    row(sourceHeading("Python", "Who"), escapeHtml(pythonWho), "Derived from normalized source and destination fields."),
    row(sourceHeading("Python", "What"), escapeHtml(pythonWhat), "Derived from stored Suricata and Zeek findings."),
    row(sourceHeading("Python", "When"), escapeHtml(pythonWhen), "Derived from normalized first_seen and last_seen timestamps."),
    row(sourceHeading("Python", "Where"), escapeHtml(pythonWhere), "Derived from normalized IP, port, and protocol fields."),
    row(sourceHeading("Python", "How It Was Detected"), escapeHtml(pythonHow), "Correlation is performed by Python before the model request."),
    ...aiOverview.slice(1)
  ].join("");

  renderSensorFindings(data);

  const vtRows = data.virustotal_verifications || [];
  const virustotalHistory = vtRows.map((item) => row(
    `${item.ip_address || "No eligible public IP"} · ${label(item.request_state)}`,
    `${label(item.verdict)} · ${label(item.interpretation)}`,
    `malicious ${item.malicious_count || 0} · suspicious ${item.suspicious_count || 0} · ${displayTimestamp(item.checked_at)}`
  )).join("");
  els.intel.innerHTML = [
    intelEndpointRow("Source IP", data.src_ip_profile),
    intelEndpointRow("Destination IP", data.dest_ip_profile),
    renderCaseThreatIntel(data),
    renderZeekThreatIntel(data),
    row(
      "VirusTotal Verification",
      vtRows.length ? `${vtRows.length} stored verification record${vtRows.length === 1 ? "" : "s"}` : "Not requested",
      "Post-classification verification only. VirusTotal does not determine or lower the model classification."
    ),
    vtRows.length ? `
      <section class="bounded-history">
        <div class="bounded-history-head">
          <strong>VirusTotal History</strong>
          <span>${vtRows.length}</span>
        </div>
        <div class="bounded-history-list">${virustotalHistory}</div>
      </section>
    ` : "",
  ].join("");

  els.review.innerHTML = [
    row("Review Status", data.review_status || "No review item", data.due_at ? `Due ${data.due_at}` : ""),
    row("Analyst Action", data.analyst_action || "No analyst override", data.analyst_name ? `by ${data.analyst_name}` : ""),
    row("Analyst Notes", data.analyst_notes || "No notes"),
  ].join("");
  els.reviewName.value = data.analyst_name || "";
  els.reviewNotes.value = data.analyst_notes || "";
  setStatus("", data.review_status ? `Current review status: ${data.review_status}` : "No review item stored yet.");

  renderZeekContext(data);
  renderAiAudit(data);
  els.updated.textContent = new Date().toLocaleTimeString();
}

function classificationForAction(action) {
  if (action === "log_only") return "Safe";
  if (action === "escalate") return "Dangerous";
  return "Analyst Review Required";
}

async function submitReview(event) {
  event.preventDefault();
  if (!currentInvestigation?.detection_id) return;
  const action = els.reviewAction.value;
  try {
    await sendJson(`/api/reviews/${currentInvestigation.detection_id}`, "POST", {
      action,
      analyst_name: els.reviewName.value,
      notes: els.reviewNotes.value,
      tuning_label: els.reviewLabel.value,
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
  setActionStatus("", "The model comparison is being queued for sequential background processing.");
  const progressTimer = window.setInterval(() => {
    refreshComparisonOnly().catch(() => {});
  }, 3000);
  try {
    const result = await sendJson(`/api/cases/${encodeURIComponent(currentInvestigation.case_uid)}/ai-comparison`, "POST");
    await refresh();
    setActionStatus("ok", `Comparison ${result.comparison_uid} queued with ${result.expected_candidate_count || 0} model requests.`);
  } catch (error) {
    setActionStatus("error", error.message);
  } finally {
    window.clearInterval(progressTimer);
    els.compare.disabled = false;
  }
}

async function refreshComparisonOnly() {
  if (!currentInvestigation?.case_uid) return;
  const runs = await getJson(
    `/api/cases/${encodeURIComponent(currentInvestigation.case_uid)}/ai-comparisons?limit=10`
  );
  await renderComparisonRuns(runs);
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
      await refreshComparisonOnly();
    } else {
      await renderComparisonRuns([]);
    }
  } catch (error) {
    els.updated.textContent = "Case API error";
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

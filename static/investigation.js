const params = new URLSearchParams(window.location.search);
const detectionId = params.get("id");

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
  alert: document.querySelector("#inv-alert"),
  ai: document.querySelector("#inv-ai"),
  scoring: document.querySelector("#inv-scoring"),
  intel: document.querySelector("#inv-intel"),
  zeek: document.querySelector("#inv-zeek"),
  createEvidence: document.querySelector("#inv-create-evidence"),
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

function intelBlock(title, profile, providers, asset) {
  return `
    <div class="workbook-row">
      <strong>${title}</strong>
      <p>${profile?.ip_address || "unknown"} · ${profile?.location || "No local profile"} · ${profile?.scope || "unknown"}</p>
      <small>
        ${asset ? `Asset: ${asset.name} (${label(asset.device_type)}) score ${asset.asset_score}` : "No registered asset"}
      </small>
      <div class="intel-provider-results">
        ${(providers || []).map((provider) => `
          <div class="intel-provider-result ${provider.result}">
            <strong>${escapeHtml(provider.label || label(provider.name))}</strong>
            <span>${provider.result === "not_active" ? "Not active" : provider.result === "matched" ? `${provider.match_count} match${provider.match_count === 1 ? "" : "es"}` : "No match"}</span>
            ${(provider.matches || []).slice(0, 3).map((match) => `<small>${escapeHtml(match.category || "malicious indicator")} · confidence ${match.confidence ?? "not supplied"}${match.malware_family ? ` · ${escapeHtml(match.malware_family)}` : ""}</small>`).join("")}
          </div>
        `).join("")}
      </div>
    </div>
  `;
}

function renderZeekContext(data) {
  const context = data.zeek_context || {};
  const items = context.items || [];
  const byType = items.reduce((acc, item) => {
    const key = item.log_type || "unknown";
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});
  const evidenceRows = data.incident_evidence || [];
  els.zeek.innerHTML = `
    <div class="workbook-row">
      <strong>Correlation Window</strong>
      <p>${context.window_start || "unknown"} to ${context.window_end || "unknown"}</p>
      <small>${items.length} Zeek rows matched by detection IPs and time window.</small>
    </div>
    <div class="workbook-row">
      <strong>Log Types</strong>
      <p>${Object.entries(byType).map(([key, value]) => `${label(key)} ${value}`).join(" · ") || "No Zeek context rows found."}</p>
      <small>Notice rows can initiate detections. Weird and protocol rows are supporting context.</small>
    </div>
    ${evidenceRows.slice(0, 5).map((item) => `
      <div class="workbook-row">
        <strong>Incident Evidence #${item.id}</strong>
        <p>${item.status || item.summary_status || "unknown"} · ${item.incident_directory || "no incident directory"}</p>
        <small>${item.zeek_logs_path || "No Zeek evidence file"} · ${item.evidence_manifest_path || "No manifest"}</small>
      </div>
    `).join("")}
    <div class="mini-list dense expanded-list">
      ${items.slice(0, 25).map((item) => `
        <div>
          <strong>${escapeHtml(item.event_name || item.log_type || "Zeek event")}</strong>
          <small>${escapeHtml(item.message || "No message")} · ${escapeHtml(item.timestamp || "")}</small>
          <small>${escapeHtml(item.source_ip || "unknown")}:${item.source_port || ""} -> ${escapeHtml(item.destination_ip || "unknown")}:${item.destination_port || ""} ${escapeHtml(item.protocol || "")}</small>
        </div>
      `).join("") || `<div class="empty">No Zeek context was found for this detection yet.</div>`}
    </div>
  `;
}

function render(data) {
  currentInvestigation = data;
  els.title.textContent = `${label(data.detection_type)} #${data.detection_id}`;
  els.finalScore.textContent = data.final_score ?? data.python_initial_score ?? 0;
  els.decision.textContent = data.final_classification || "No decision";
  els.action.textContent = data.final_action || "No action";
  els.aiConfidence.textContent = data.ai_confidence || "None";
  els.aiClassification.textContent = data.ai_classification || "No AI opinion";
  els.sensorState.textContent = label(data.sensor_state || "unknown");
  els.agreementState.textContent = `${label(data.agreement_state || "unknown")} · ${label(data.correlation_method || "none")}`;
  els.timestamp.textContent = displayTimestamp(data.timestamp || data.first_seen);

  const findings = data.sensor_findings || [];
  els.alert.innerHTML = [
    row(
      "Fusion Summary",
      `${label(data.sensor_state || "unknown")} · ${label(data.agreement_state || "unknown")}`,
      `${label(data.correlation_method || "none")} · confidence ${data.correlation_confidence ?? "unknown"}${data.community_id ? ` · Community ID ${escapeHtml(data.community_id)}` : ""}`
    ),
    ...findings.map((finding) => row(
      `${label(finding.sensor)} · ${label(finding.finding_type)}`,
      escapeHtml(finding.finding_name || "Unnamed finding"),
      `${escapeHtml(displayTimestamp(finding.finding_timestamp))} · ${escapeHtml(finding.source_ip || "unknown")}:${finding.source_port || ""} -> ${escapeHtml(finding.destination_ip || "unknown")}:${finding.destination_port || ""} ${escapeHtml(finding.protocol || "")} · severity ${finding.severity ?? "unknown"} · confidence ${finding.confidence ?? "unknown"}`
    )),
    findings.length ? "" : row("Primary Finding", data.signature, `${data.category || "unknown category"} · priority ${data.priority || "unknown"}`),
    row("Traffic", `${data.src_ip || "unknown"}:${data.src_port || ""} -> ${data.dest_ip || "unknown"}:${data.dest_port || ""}`, data.protocol || ""),
    row("Timestamp", data.timestamp || data.first_seen || "unknown"),
  ].filter(Boolean).join("");

  els.ai.innerHTML = [
    row("Classification", data.ai_classification || "No AI opinion", `${data.ai_confidence || "No"} confidence`),
    row("AI Profile UID", data.ai_profile_uid || "legacy-profile", "Selected Admin profile stamped into this report"),
    row("Model Identity", data.ai_model_identity || "unknown model", `provider ${data.ai_model_provider || "unknown"} · name ${data.ai_model_name || "unknown"}`),
    row("Model Run", data.ai_model_run_id || "not recorded", `${data.ai_prompt_version || "unknown prompt"} · ${data.ai_elapsed_ms ?? 0}ms`),
    row("Reason", data.ai_reason || "No AI reason stored."),
    row("Recommended Action", data.ai_recommended_action || "none", `Risk adjustment ${data.ai_risk_adjustment ?? 0}`),
  ].join("");

  els.scoring.innerHTML = [
    row("Python Score", data.python_initial_score ?? 0, "Deterministic correlation score"),
    row("AI Adjustment", data.ai_risk_adjustment ?? 0, "Bounded model second opinion"),
    row("Correlation", `${data.alert_count || 0} sensor events · ${data.unique_dest_ports || 0} destination ports · ${data.unique_dest_hosts || 0} hosts`, `${data.time_window_seconds || 0}s window · ${label(data.correlation_method || "single_sensor")}`),
    row("MITRE", data.mitre_id ? `${data.mitre_id} · ${data.mitre_name || ""}` : "No MITRE mapping"),
  ].join("");

  els.intel.innerHTML = [
    intelBlock("Source IP", data.src_ip_profile, data.src_threat_intel, data.src_asset),
    intelBlock("Destination IP", data.dest_ip_profile, data.dest_threat_intel, data.dest_asset),
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
      <pre class="raw-json">${data.ai_raw_response || "No raw AI response stored."}</pre>
    </div>
  `;

  renderZeekContext(data);
  els.updated.textContent = new Date().toLocaleTimeString();
}

function classificationForAction(action) {
  if (action === "log_only") return "Safe";
  if (action === "would_block" || action === "temporary_block") return "Dangerous";
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

async function createEvidence() {
  if (!currentInvestigation?.detection_id) return;
  els.createEvidence.disabled = true;
  els.createEvidence.textContent = "Creating...";
  try {
    await sendJson(`/api/detections/${currentInvestigation.detection_id}/investigation`, "POST", {
      seconds_before: 120,
      seconds_after: 120,
      ip_filter_enabled: true
    });
    await refresh();
  } catch (error) {
    els.zeek.innerHTML = `<div class="empty">${error.message}</div>`;
  } finally {
    els.createEvidence.disabled = false;
    els.createEvidence.textContent = "Create Evidence";
  }
}

async function refresh() {
  if (!detectionId) {
    els.updated.textContent = "Missing detection id";
    els.alert.innerHTML = `<div class="empty">Open this page from an alert, AI opinion, evidence row, or review item.</div>`;
    return;
  }
  try {
    render(await getJson(`/api/investigation/${encodeURIComponent(detectionId)}`));
  } catch (error) {
    els.updated.textContent = "Investigation API error";
    els.alert.innerHTML = `<div class="empty">${error.message}</div>`;
  }
}

refresh();
els.reviewForm.addEventListener("submit", submitReview);
els.createEvidence.addEventListener("click", createEvidence);

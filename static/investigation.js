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
  pcapCount: document.querySelector("#inv-pcap-count"),
  alert: document.querySelector("#inv-alert"),
  ai: document.querySelector("#inv-ai"),
  scoring: document.querySelector("#inv-scoring"),
  intel: document.querySelector("#inv-intel"),
  pcapProcess: document.querySelector("#inv-pcap-process"),
  pcaps: document.querySelector("#inv-pcaps"),
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

function formatBytes(bytes) {
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  let value = Number(bytes);
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
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

function processStep(number, title, status, body, meta = "") {
  return `
    <div class="process-step ${status || ""}">
      <div class="process-number">${number}</div>
      <div class="process-content">
        <div class="process-titleline">
          <strong>${escapeHtml(title)}</strong>
          <span class="process-status">${label(status || "recorded")}</span>
        </div>
        <p>${escapeHtml(body || "No detail recorded.")}</p>
        ${meta ? `<small class="process-meta">${escapeHtml(meta)}</small>` : ""}
      </div>
    </div>
  `;
}

function intelBlock(title, profile, otx, asset) {
  return `
    <div class="workbook-row">
      <strong>${title}</strong>
      <p>${profile?.ip_address || "unknown"} · ${profile?.location || "No local profile"} · ${profile?.scope || "unknown"}</p>
      <small>
        ${asset ? `Asset: ${asset.name} (${label(asset.device_type)}) score ${asset.asset_score}` : "No registered asset"}
      </small>
      <small>
        ${otx ? `OTX ${otx.reputation} · malicious ${otx.malicious_count || 0} · suspicious ${otx.suspicious_count || 0} · ${otx.lookup_result || "No detail"}` : "No cached OTX lookup"}
      </small>
    </div>
  `;
}

function renderPcapProcess(data) {
  const inventory = data.pcap_files || {};
  const related = (inventory.files || []).filter((file) => file.related);
  const evidenceRows = data.incident_evidence || inventory.incident_evidence || [];
  const generatedRows = evidenceRows.filter((row) => row.summary_status === "generated");
  const sentRows = evidenceRows.filter((row) => Number(row.ai_sent || 0) === 1);
  const failedRows = evidenceRows.filter((row) => row.summary_status && row.summary_status !== "generated");
  const firstSummary = generatedRows[0];
  const summaryPaths = generatedRows.map((row) => row.pcap_summary_path).filter(Boolean);
  const pcapPaths = evidenceRows.map((row) => row.incident_pcap_path).filter(Boolean);
  const modelRuns = [...new Set(sentRows.map((row) => row.ai_model_run_id).filter(Boolean))];
  const pcapSummaryIncluded = Number(data.ai_pcap_summary_included || 0) === 1;
  const aiUnavailable = /ai model unavailable|timed out|timeout/i.test(data.ai_reason || "");
  const pcapPromptProof = pcapSummaryIncluded
    ? `pcap_summary ${data.ai_pcap_summary_chars || 0} chars · sha256 ${data.ai_pcap_summary_sha256 || "not recorded"} · full prompt ${data.ai_prompt_chars || 0} chars`
    : "Prompt proof was not recorded for this AI report.";
  const aiStepStatus = pcapSummaryIncluded
    ? aiUnavailable ? "attempted" : "complete"
    : sentRows.length ? "attempted" : "not_sent";
  const aiStepBody = pcapSummaryIncluded
    ? `${generatedRows.length}/${evidenceRows.length} packet summaries were included in the Ollama prompt attempt. Raw PCAP files are not uploaded.`
    : `${sentRows.length}/${evidenceRows.length} summaries marked as included with the Ollama prompt. Raw PCAP files are not uploaded.`;
  const aiStepMeta = pcapSummaryIncluded
    ? `${modelRuns.length ? `Model run ID: ${modelRuns.join(", ")}` : `Model run ID: ${data.ai_model_run_id || "recorded in report"}`} · ${data.ai_model_identity || "unknown model"} · ${pcapPromptProof}${aiUnavailable ? ` · Model response: ${data.ai_reason}` : ""}`
    : aiUnavailable
      ? `Ollama request failed before prompt audit was stored: ${data.ai_reason}`
      : "No model run ID linked to packet evidence yet.";
  const timeStart = evidenceRows[0]?.incident_start_time || data.first_seen || data.timestamp || "unknown";
  const timeEnd = evidenceRows[0]?.incident_end_time || data.last_seen || data.timestamp || "unknown";

  els.pcapProcess.innerHTML = `
    ${processStep(
      1,
      "Detection selected a packet window",
      data.detection_id ? "complete" : "pending",
      `${data.signature || "Suricata alert"} at ${data.timestamp || data.first_seen || "unknown time"}`,
      `Incident window: ${timeStart} to ${timeEnd}. Configured expansion: ${inventory.window_minutes ?? "unknown"} minutes.`
    )}
    ${processStep(
      2,
      "Rolling PCAP files matched the window",
      related.length ? "complete" : "empty",
      `${related.length} related rolling PCAP files found in ${inventory.directory || "the configured PCAP directory"}.`,
      pcapPaths.length ? `Selected for AI summary: ${pcapPaths.slice(0, 3).join(" | ")}` : "No PCAP files selected for AI summary yet."
    )}
    ${processStep(
      3,
      "tshark converted packets into text",
      generatedRows.length ? "complete" : failedRows.length ? "failed" : "pending",
      `${generatedRows.length}/${evidenceRows.length} packet summaries generated. Raw PCAP bytes stay local and are not sent to the model.`,
      firstSummary
        ? `First summary: ${firstSummary.pcap_summary_path} (${firstSummary.summary_packet_count || 0} packets, filter ${firstSummary.display_filter || "none"})`
        : failedRows[0]?.summary_error || "No summary file has been generated for this detection."
    )}
    ${processStep(
      4,
      "Python sent the summary to the AI model",
      aiStepStatus,
      aiStepBody,
      aiStepMeta
    )}
    ${processStep(
      5,
      "SQLite stored the evidence chain",
      evidenceRows.length ? "complete" : "pending",
      `${evidenceRows.length} incident_evidence rows stored for detection #${data.detection_id || "unknown"}.`,
      summaryPaths.length ? `Summary paths: ${summaryPaths.slice(0, 3).join(" | ")}` : "No summary paths stored yet."
    )}
  `;
}

function renderPcaps(inventory) {
  const related = (inventory.files || []).filter((file) => file.related);
  const evidenceRows = inventory.incident_evidence || currentInvestigation?.incident_evidence || [];
  const sentRows = evidenceRows.filter((row) => Number(row.ai_sent || 0) === 1);
  els.pcapCount.textContent = related.length;
  els.pcaps.innerHTML = `
    <div class="pcap-summary">
      <strong>${sentRows.length}</strong>
      <span>packet summaries sent to AI · ${evidenceRows.length} evidence rows stored</span>
    </div>
    ${evidenceRows.map((row) => `
      <div class="pcap-item ai-evidence ${Number(row.ai_sent || 0) === 1 ? "sent" : "not-sent"}">
        <div class="row tight">
          <strong>${Number(row.ai_sent || 0) === 1 ? "Included in AI Prompt" : "Prepared Evidence"}</strong>
          <span>${row.summary_status || "unknown"}</span>
        </div>
        <p>${escapeHtml(row.incident_pcap_path || "No PCAP path recorded")}</p>
        <p>${escapeHtml(row.pcap_summary_path || "No packet summary path recorded")}</p>
        <small>
          ${formatBytes(row.file_size_bytes)} · ${row.capture_label || "capture"} · packets ${row.summary_packet_count ?? 0}
          · model run ${row.ai_model_run_id || "not sent"}
        </small>
        <small>
          window ${row.incident_start_time || "unknown"} to ${row.incident_end_time || "unknown"}
          ${row.display_filter ? ` · filter ${escapeHtml(row.display_filter)}` : ""}
        </small>
        ${row.summary_error ? `<small class="error-text">${escapeHtml(row.summary_error)}</small>` : ""}
        ${row.pcap_summary_preview ? `
          <pre class="raw-json packet-preview">${escapeHtml(row.pcap_summary_preview)}${row.pcap_summary_truncated ? "\n... truncated in dashboard preview" : ""}</pre>
        ` : ""}
      </div>
    `).join("") || `<div class="empty">No AI packet evidence rows stored for this detection yet.</div>`}
    <div class="pcap-summary">
      <strong>${related.length}</strong>
      <span>related rolling files · ${inventory.files?.length || 0} total in ${inventory.directory || "pcap directory"}</span>
    </div>
    ${related.map((file) => `
      <div class="pcap-item ${file.label}">
        <div class="row tight">
          <strong>${file.name}</strong>
          <span>${file.label}</span>
        </div>
        <p>${file.path}</p>
        <small>${formatBytes(file.size_bytes)} · modified ${file.modified_at}</small>
      </div>
    `).join("") || `<div class="empty">No PCAP files matched this detection time window.</div>`}
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

  els.alert.innerHTML = [
    row("Signature", data.signature, `${data.category || "unknown category"} · priority ${data.priority || "unknown"}`),
    row("Traffic", `${data.src_ip || "unknown"}:${data.src_port || ""} -> ${data.dest_ip || "unknown"}:${data.dest_port || ""}`, data.protocol || ""),
    row("Timestamp", data.timestamp || data.first_seen || "unknown"),
  ].join("");

  els.ai.innerHTML = [
    row("Classification", data.ai_classification || "No AI opinion", `${data.ai_confidence || "No"} confidence`),
    row("AI Profile UID", data.ai_profile_uid || "legacy-profile", "Selected Admin profile stamped into this report"),
    row("Model Identity", data.ai_model_identity || "unknown model", `provider ${data.ai_model_provider || "unknown"} · name ${data.ai_model_name || "unknown"}`),
    row("Model Run", data.ai_model_run_id || "not recorded", `${data.ai_prompt_version || "unknown prompt"} · ${data.ai_elapsed_ms ?? 0}ms`),
    row(
      "Prompt Audit",
      Number(data.ai_pcap_summary_included || 0) === 1 ? "PCAP summary text included in Ollama prompt" : "No packet summary recorded in prompt audit",
      Number(data.ai_pcap_summary_included || 0) === 1
        ? `pcap_summary ${data.ai_pcap_summary_chars || 0} chars · sha256 ${data.ai_pcap_summary_sha256 || "not recorded"}`
        : "New detections after this update will record prompt hash and summary size."
    ),
    row("Reason", data.ai_reason || "No AI reason stored."),
    row("Recommended Action", data.ai_recommended_action || "none", `Risk adjustment ${data.ai_risk_adjustment ?? 0}`),
  ].join("");

  els.scoring.innerHTML = [
    row("Python Score", data.python_initial_score ?? 0, "Deterministic correlation score"),
    row("AI Adjustment", data.ai_risk_adjustment ?? 0, "Bounded model second opinion"),
    row("Correlation", `${data.alert_count || 0} alerts · ${data.unique_dest_ports || 0} destination ports · ${data.unique_dest_hosts || 0} hosts`, `${data.time_window_seconds || 0}s window`),
    row("MITRE", data.mitre_id ? `${data.mitre_id} · ${data.mitre_name || ""}` : "No MITRE mapping"),
  ].join("");

  els.intel.innerHTML = [
    intelBlock("Source IP", data.src_ip_profile, data.src_otx, data.src_asset),
    intelBlock("Destination IP", data.dest_ip_profile, data.dest_otx, data.dest_asset),
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

  renderPcapProcess(data);
  renderPcaps(data.pcap_files || {});
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

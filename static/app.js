const els = {
  totalAlerts: document.querySelector("#total-alerts"),
  totalDetections: document.querySelector("#total-detections"),
  topDetection: document.querySelector("#top-detection"),
  systemMode: document.querySelector("#system-mode"),
  detailTitle: document.querySelector("#detail-title"),
  detectionDetail: document.querySelector("#detection-detail"),
  decisionEvidence: document.querySelector("#decision-evidence"),
  pcapFiles: document.querySelector("#pcap-files"),
  mode: document.querySelector("#mode"),
  updated: document.querySelector("#updated"),
  alerts: document.querySelector("#alerts"),
  ollamaReports: document.querySelector("#ollama-reports"),
  detections: document.querySelector("#detections"),
  reviews: document.querySelector("#reviews"),
  allowlist: document.querySelector("#allowlist"),
  allowlistForm: document.querySelector("#allowlist-form"),
  enrichment: document.querySelector("#enrichment"),
  events: document.querySelector("#events"),
  checkOllama: document.querySelector("#check-ollama"),
  refresh: document.querySelector("#refresh")
};

let selectedDetectionType = null;

if (window.location.hash.startsWith("#type=")) {
  selectedDetectionType = decodeURIComponent(window.location.hash.slice(6));
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
  if (!response.ok) throw new Error(data.detail || `${path} returned ${response.status}`);
  return data;
}

function detectionLabel(value) {
  if (!value) return "Unknown";
  return value.replaceAll("_", " ").replace(/\b\w/g, (char) => char.toUpperCase());
}

function renderMetrics(metrics) {
  const detections = metrics.detections_by_type || [];
  if (!selectedDetectionType && detections[0]) {
    selectedDetectionType = detections[0].detection_type;
  }
  els.totalAlerts.textContent = metrics.total_alerts ?? 0;
  els.totalDetections.textContent = metrics.total_detections ?? 0;
  els.topDetection.textContent = detections[0] ? detectionLabel(detections[0].detection_type) : "None";
  els.systemMode.textContent = metrics.mode || "alert_only";
  els.mode.textContent = metrics.mode || "alert_only";

  const max = Math.max(1, ...detections.map((item) => item.count));
  els.detections.innerHTML = detections.map((item) => `
    <button
      class="list-item detection-button ${item.detection_type === selectedDetectionType ? "selected" : ""}"
      type="button"
      data-detection-type="${item.detection_type}"
      aria-pressed="${item.detection_type === selectedDetectionType ? "true" : "false"}"
      title="Open ${detectionLabel(item.detection_type)} investigation"
    >
      <div class="row">
        <strong>${detectionLabel(item.detection_type)}</strong>
        <span>${item.count}</span>
      </div>
      <div class="bar"><span style="--value:${(item.count / max) * 100}%"></span></div>
      <small>Open investigation</small>
    </button>
  `).join("") || `<div class="empty">No detections yet. Start ingest and generate test traffic.</div>`;
}

function renderAlerts(alerts) {
  els.alerts.innerHTML = alerts.map((alert) => `
    <article class="alert">
      <time>${alert.timestamp || ""}</time>
      <div>
        <strong>${alert.signature || "Suricata alert"}</strong>
        <p>
          ${alert.src_ip || "unknown"}:${alert.src_port || ""} ->
          ${alert.dest_ip || "unknown"}:${alert.dest_port || ""}
          ${alert.protocol || ""}
        </p>
        <p>${alert.category || "unknown"} · priority ${alert.priority || "unknown"}</p>
      </div>
    </article>
  `).join("") || `<div class="empty">No alerts in SQLite yet. Run the ingest command while Suricata writes eve.json.</div>`;
}

function classificationClass(value) {
  const normalized = String(value || "").toLowerCase();
  if (normalized.includes("dangerous")) return "danger";
  if (normalized.includes("human")) return "review";
  return "safe";
}

function renderOllamaReports(reports) {
  els.ollamaReports.innerHTML = reports.map((report) => `
    <article class="alert ollama ${classificationClass(report.classification)}">
      <time>${report.created_at || report.timestamp || ""}</time>
      <div>
        <div class="row tight">
          <strong>${report.classification || "Ollama opinion"}</strong>
          <span>${report.confidence || "Unknown"} confidence</span>
        </div>
        <p>
          ${report.src_ip || "unknown"} -> ${report.dest_ip || "unknown"}
          ${report.signature || ""}
        </p>
        <p>${report.reason || "No reason returned."}</p>
        <p>Recommended action: ${report.recommended_action || "none"} · risk adjustment ${report.risk_adjustment ?? 0}</p>
      </div>
    </article>
  `).join("") || `<div class="empty">No Ollama opinions yet. Start ingest and confirm Ollama is reachable.</div>`;
}

function renderEvents(events) {
  els.events.innerHTML = events.map((event) => `
    <div class="list-item log ${event.level || "info"}">
      <div class="row tight">
        <strong>${event.component || "system"}</strong>
        <span>${event.created_at || ""}</span>
      </div>
      <p>${event.message || ""}</p>
      ${event.details ? `<small>${event.details}</small>` : ""}
    </div>
  `).join("") || `<div class="empty">No runtime logs yet. Start ingest or check Ollama.</div>`;
}

function renderDetectionDetail(detail) {
  if (!detail || !detail.detection_type) {
    els.detailTitle.textContent = "Detection Detail";
    els.detectionDetail.innerHTML = `<div class="empty">Select a detection type to investigate.</div>`;
    return;
  }

  const summary = detail.summary || {};
  const timeline = detail.timeline || [];
  const ips = detail.ips || [];
  const recent = detail.recent || [];
  const max = Math.max(1, ...timeline.map((item) => item.count));

  els.detailTitle.textContent = detectionLabel(detail.detection_type);
  els.detectionDetail.innerHTML = `
    <div class="detail-card">
      <span>Total</span>
      <strong>${summary.total || 0}</strong>
      <small>avg score ${Math.round(summary.avg_score || 0)} · max ${summary.max_score || 0}</small>
    </div>
    <div class="detail-card wide">
      <span>Activity Over Time</span>
      <div class="timeline">
        ${timeline.map((item) => `
          <div class="timeline-row">
            <time>${item.bucket || "unknown"}</time>
            <div class="bar"><span style="--value:${(item.count / max) * 100}%"></span></div>
            <strong>${item.count}</strong>
          </div>
        `).join("") || `<div class="empty">No timeline data.</div>`}
      </div>
    </div>
    <div class="detail-card">
      <span>IP Addresses</span>
      <div class="mini-list">
        ${ips.map((item) => `
          <div>
            <strong>${item.ip_address}</strong>
            <small>${item.location} · ${item.scope} · seen ${item.count}</small>
          </div>
        `).join("") || `<small>No IP data.</small>`}
      </div>
    </div>
    <div class="detail-card wide">
      <span>Recent ${detectionLabel(detail.detection_type)} Alerts</span>
      <div class="mini-list">
        ${recent.map((item) => `
          <div>
            <strong>${item.src_ip || "unknown"} -> ${item.dest_ip || "unknown"}</strong>
            <small>${item.signature || "Detection"} · score ${item.python_initial_score || 0} · ${item.ollama_classification || "no Ollama"}</small>
          </div>
        `).join("") || `<small>No recent rows.</small>`}
      </div>
    </div>
  `;
}

function renderEnrichment(status) {
  const sources = status.sources || [];
  const topIps = status.top_ips || [];
  els.enrichment.innerHTML = `
    ${sources.map((source) => `
      <div class="list-item enrichment-source ${source.status}">
        <div class="row tight">
          <strong>${source.name}</strong>
          <span>${source.status}</span>
        </div>
        <p>${source.notes}</p>
      </div>
    `).join("")}
    <div class="list-item">
      <div class="row tight">
        <strong>Threat intel lookups</strong>
        <span>${status.lookup_count || 0}</span>
      </div>
      <p>External API lookups are tracked here when enabled.</p>
    </div>
    ${topIps.slice(0, 8).map((item) => `
      <div class="list-item">
        <div class="row tight">
          <strong>${item.ip_address}</strong>
          <span>${item.scope}</span>
        </div>
        <p>${item.location}</p>
        <small>${item.source} · seen ${item.count}</small>
      </div>
    `).join("")}
  `;
}

function formatBytes(bytes) {
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
}

function renderPcapFiles(inventory) {
  const files = (inventory.files || []).filter((file) => file.related).slice(0, 20);
  const allFiles = inventory.files || [];
  els.pcapFiles.innerHTML = `
    <div class="pcap-summary">
      <strong>${files.length}</strong>
      <span>related files · ${allFiles.length} total in ${inventory.directory || "pcap directory"}</span>
    </div>
    ${files.map((file) => `
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

function renderDecisionEvidence(rows) {
  els.decisionEvidence.innerHTML = rows.map((row) => `
    <article class="evidence-item">
      <div class="row tight">
        <strong>${row.final_classification || "Decision"}</strong>
        <span>${row.final_action || "none"} · score ${row.final_score ?? 0}</span>
      </div>
      <div class="evidence-chain">
        <div>
          <span>Alert</span>
          <strong>${row.signature || "Suricata alert"}</strong>
          <small>${row.src_ip || "unknown"}:${row.src_port || ""} -> ${row.dest_ip || "unknown"}:${row.dest_port || ""} · priority ${row.priority || "unknown"}</small>
        </div>
        <div>
          <span>Correlation</span>
          <strong>${detectionLabel(row.detection_type)}</strong>
          <small>${row.alert_count || 0} alerts · ${row.unique_dest_ports || 0} ports · ${row.mitre_id || "no MITRE"}</small>
        </div>
        <div>
          <span>Scoring</span>
          <strong>Python ${row.python_initial_score ?? 0} + Ollama ${row.ollama_risk_adjustment ?? 0}</strong>
          <small>Final score ${row.final_score ?? 0}</small>
        </div>
        <div>
          <span>Ollama</span>
          <strong>${row.ollama_classification || "No opinion"} ${row.ollama_confidence ? `(${row.ollama_confidence})` : ""}</strong>
          <small>${row.ollama_reason || "No Ollama reason stored."}</small>
        </div>
        <div>
          <span>Analyst</span>
          <strong>${row.review_status || "No review"}</strong>
          <small>${row.analyst_action || "No analyst override"} ${row.analyst_name ? `by ${row.analyst_name}` : ""}</small>
        </div>
      </div>
    </article>
  `).join("") || `<div class="empty">No decision evidence rows for this selection yet.</div>`;
}

function formatRemaining(seconds) {
  if (seconds === null || seconds === undefined) return "No expiry";
  if (seconds <= 0) return "Expired";
  const hours = Math.ceil(seconds / 3600);
  if (hours < 48) return `${hours}h left`;
  return `${Math.ceil(hours / 24)}d left`;
}

function renderAllowlist(entries) {
  els.allowlist.innerHTML = entries.map((entry) => `
    <div class="list-item allow-item">
      <div class="row tight">
        <strong>${entry.name || entry.ip_address}</strong>
        <span>${formatRemaining(entry.remaining_seconds)}</span>
      </div>
      <p>${entry.ip_address}</p>
      <p>${entry.reason || "No reason provided."}</p>
      <small>Added by ${entry.added_by || "unknown"} · expires ${entry.expiry_time || "never"}</small>
      <button class="text-button" type="button" data-allow-remove="${entry.id}">Deactivate</button>
    </div>
  `).join("") || `<div class="empty">No active allowlist entries.</div>`;
}

function renderReviews(reviews) {
  els.reviews.innerHTML = reviews.map((review) => `
    <div class="list-item review ${review.review_status}">
      <div class="row tight">
        <strong>${review.original_classification || "Human Review"}</strong>
        <span>score ${review.original_score}</span>
      </div>
      <p>${review.src_ip || "unknown"} -> ${review.dest_ip || "unknown"}</p>
      <p>${review.signature || detectionLabel(review.detection_type)}</p>
      <small>Due ${review.due_at} · ${review.review_status}</small>
      ${review.ollama_reason ? `<small>Ollama: ${review.ollama_reason}</small>` : ""}
      <div class="review-actions">
        <input type="text" placeholder="Analyst" data-review-name="${review.detection_id}">
        <input type="number" min="0" max="100" placeholder="Score" data-review-score="${review.detection_id}">
        <select data-review-action="${review.detection_id}">
          <option value="confirm">Confirm original</option>
          <option value="log_only">Override: log only</option>
          <option value="human_review">Override: keep review</option>
          <option value="would_block">Override: would block</option>
          <option value="temporary_block">Override: temporary block</option>
        </select>
        <textarea placeholder="Notes" data-review-notes="${review.detection_id}"></textarea>
        <button class="wide-button" type="button" data-review-submit="${review.detection_id}">Save Review</button>
      </div>
    </div>
  `).join("") || `<div class="empty">No human-review alerts waiting.</div>`;
}

async function refresh() {
  try {
    const detailPath = selectedDetectionType
      ? `/api/detection-detail?detection_type=${encodeURIComponent(selectedDetectionType)}&limit=50`
      : null;
    const pcapPath = selectedDetectionType
      ? `/api/pcap-files?detection_type=${encodeURIComponent(selectedDetectionType)}`
      : "/api/pcap-files";
    const evidencePath = selectedDetectionType
      ? `/api/decision-evidence?detection_type=${encodeURIComponent(selectedDetectionType)}&limit=20`
      : "/api/decision-evidence?limit=20";
    const [metrics, alerts, ollamaReports, reviews, allowlist, enrichment, events, detail, pcaps, evidence] = await Promise.all([
      getJson("/api/metrics"),
      getJson("/api/alerts?limit=50"),
      getJson("/api/ollama-reports?limit=50"),
      getJson("/api/reviews?limit=25"),
      getJson("/api/allowlist?limit=25"),
      getJson("/api/enrichment-status?limit=25"),
      getJson("/api/events?limit=40"),
      detailPath ? getJson(detailPath) : Promise.resolve(null),
      getJson(pcapPath),
      getJson(evidencePath)
    ]);
    renderMetrics(metrics);
    renderAlerts(alerts);
    renderOllamaReports(ollamaReports);
    renderReviews(reviews);
    renderAllowlist(allowlist);
    renderEnrichment(enrichment);
    renderDetectionDetail(detail);
    renderPcapFiles(pcaps);
    renderDecisionEvidence(evidence);
    renderEvents(events);
    els.updated.textContent = new Date().toLocaleTimeString();
  } catch (error) {
    els.updated.textContent = "Dashboard API error";
    els.alerts.innerHTML = `<div class="empty">${error.message}</div>`;
    els.ollamaReports.innerHTML = `<div class="empty">${error.message}</div>`;
    els.reviews.innerHTML = `<div class="empty">${error.message}</div>`;
    els.allowlist.innerHTML = `<div class="empty">${error.message}</div>`;
    els.enrichment.innerHTML = `<div class="empty">${error.message}</div>`;
    els.pcapFiles.innerHTML = `<div class="empty">${error.message}</div>`;
    els.decisionEvidence.innerHTML = `<div class="empty">${error.message}</div>`;
    els.events.innerHTML = `<div class="empty">${error.message}</div>`;
  }
}

async function checkOllama() {
  els.updated.textContent = "Checking Ollama";
  try {
    await getJson("/api/ollama-status");
  } finally {
    refresh();
  }
}

async function addAllowlistEntry(event) {
  event.preventDefault();
  const form = new FormData(els.allowlistForm);
  await sendJson("/api/allowlist", "POST", {
    ip_address: form.get("ip_address"),
    name: form.get("name"),
    duration_hours: Number(form.get("duration_hours")),
    reason: form.get("reason"),
    added_by: form.get("added_by") || "dashboard"
  });
  els.allowlistForm.reset();
  document.querySelector("#allowlist-hours").value = 24;
  refresh();
}

async function handleDashboardClick(event) {
  const detectionButton = event.target.closest ? event.target.closest("[data-detection-type]") : null;
  const detectionType = detectionButton ? detectionButton.dataset.detectionType : null;
  if (detectionType) {
    selectedDetectionType = detectionType;
    window.location.hash = `type=${encodeURIComponent(detectionType)}`;
    els.detailTitle.textContent = `Loading ${detectionLabel(detectionType)}`;
    document.querySelector("#detection-detail-panel").scrollIntoView({ behavior: "smooth", block: "start" });
    refresh();
    return;
  }

  const removeId = event.target.dataset.allowRemove;
  if (removeId) {
    await sendJson(`/api/allowlist/${removeId}`, "DELETE");
    refresh();
    return;
  }

  const detectionId = event.target.dataset.reviewSubmit;
  if (detectionId) {
    const action = document.querySelector(`[data-review-action="${detectionId}"]`).value;
    const scoreValue = document.querySelector(`[data-review-score="${detectionId}"]`).value;
    await sendJson(`/api/reviews/${detectionId}`, "POST", {
      action,
      analyst_name: document.querySelector(`[data-review-name="${detectionId}"]`).value,
      notes: document.querySelector(`[data-review-notes="${detectionId}"]`).value,
      score: action === "confirm" ? null : Number(scoreValue),
      classification: action === "log_only" ? "Safe" : action === "would_block" || action === "temporary_block" ? "Dangerous" : "Human Review Required"
    });
    refresh();
  }
}

els.refresh.addEventListener("click", refresh);
els.checkOllama.addEventListener("click", checkOllama);
els.allowlistForm.addEventListener("submit", addAllowlistEntry);
document.addEventListener("click", handleDashboardClick);
refresh();
setInterval(refresh, 2000);

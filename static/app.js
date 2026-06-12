const els = {
  totalAlerts: document.querySelector("#total-alerts"),
  totalDetections: document.querySelector("#total-detections"),
  topDetection: document.querySelector("#top-detection"),
  systemMode: document.querySelector("#system-mode"),
  mode: document.querySelector("#mode"),
  updated: document.querySelector("#updated"),
  alerts: document.querySelector("#alerts"),
  ollamaReports: document.querySelector("#ollama-reports"),
  detections: document.querySelector("#detections"),
  events: document.querySelector("#events"),
  checkOllama: document.querySelector("#check-ollama"),
  refresh: document.querySelector("#refresh")
};

async function getJson(path) {
  const response = await fetch(path, { cache: "no-store" });
  if (!response.ok) throw new Error(`${path} returned ${response.status}`);
  return response.json();
}

function detectionLabel(value) {
  if (!value) return "Unknown";
  return value.replaceAll("_", " ").replace(/\b\w/g, (char) => char.toUpperCase());
}

function renderMetrics(metrics) {
  const detections = metrics.detections_by_type || [];
  els.totalAlerts.textContent = metrics.total_alerts ?? 0;
  els.totalDetections.textContent = metrics.total_detections ?? 0;
  els.topDetection.textContent = detections[0] ? detectionLabel(detections[0].detection_type) : "None";
  els.systemMode.textContent = metrics.mode || "alert_only";
  els.mode.textContent = metrics.mode || "alert_only";

  const max = Math.max(1, ...detections.map((item) => item.count));
  els.detections.innerHTML = detections.map((item) => `
    <div class="list-item">
      <div class="row">
        <strong>${detectionLabel(item.detection_type)}</strong>
        <span>${item.count}</span>
      </div>
      <div class="bar"><span style="--value:${(item.count / max) * 100}%"></span></div>
    </div>
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

async function refresh() {
  try {
    const [metrics, alerts, ollamaReports, events] = await Promise.all([
      getJson("/api/metrics"),
      getJson("/api/alerts?limit=50"),
      getJson("/api/ollama-reports?limit=50"),
      getJson("/api/events?limit=40")
    ]);
    renderMetrics(metrics);
    renderAlerts(alerts);
    renderOllamaReports(ollamaReports);
    renderEvents(events);
    els.updated.textContent = new Date().toLocaleTimeString();
  } catch (error) {
    els.updated.textContent = "Dashboard API error";
    els.alerts.innerHTML = `<div class="empty">${error.message}</div>`;
    els.ollamaReports.innerHTML = `<div class="empty">${error.message}</div>`;
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

els.refresh.addEventListener("click", refresh);
els.checkOllama.addEventListener("click", checkOllama);
refresh();
setInterval(refresh, 2000);

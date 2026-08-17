// Main dashboard controller. It requests already-correlated cases and Zeek
// telemetry from FastAPI, then renders a read-only operational overview.
// Collection, correlation, enrichment, and AI analysis remain Python jobs.
const els = {
  summaryTimeline: document.querySelector("#summary-timeline"),
  summaryModels: document.querySelector("#summary-models"),
  summaryZeek: document.querySelector("#summary-zeek"),
  mode: document.querySelector("#mode"),
  updated: document.querySelector("#updated"),
  alerts: document.querySelector("#alerts"),
  events: document.querySelector("#events"),
  checkAiModel: document.querySelector("#check-ai-model"),
  resetLogs: document.querySelector("#reset-logs"),
  refresh: document.querySelector("#refresh")
};

let selectedSensorFilter = "all";

function investigationUrl(detectionId, caseUid = "") {
  return caseUid
    ? `/investigation?case=${encodeURIComponent(caseUid)}`
    : `/investigation?id=${encodeURIComponent(detectionId)}`;
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
  if (Array.isArray(detail)) {
    return detail.map((item) => item.msg || JSON.stringify(item)).join("; ");
  }
  return JSON.stringify(detail);
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
  if (!value) return "Timestamp unavailable";
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

function detectionLabel(value) {
  if (!value) return "Unknown";
  return value.replaceAll("_", " ").replace(/\b\w/g, (char) => char.toUpperCase());
}

function renderBars(container, rows, labelFn, valueFn, emptyText) {
  const max = Math.max(1, ...rows.map((row) => Number(valueFn(row) || 0)));
  container.innerHTML = `
    <div class="bar-list">
      ${rows.map((row) => `
        <div>
          <div class="row tight">
            <strong>${labelFn(row)}</strong>
            <span>${valueFn(row)}</span>
          </div>
          <div class="bar"><span style="--value:${(Number(valueFn(row) || 0) / max) * 100}%"></span></div>
        </div>
      `).join("") || `<div class="empty">${emptyText}</div>`}
    </div>
  `;
}

function renderSummary(summary) {
  if (summary._error) {
    const message = `${summary._error}. Restart the dashboard backend to enable this summary.`;
    els.summaryTimeline.innerHTML = `<div class="empty">${message}</div>`;
    els.summaryModels.innerHTML = `<div class="empty">${message}</div>`;
    els.summaryZeek.innerHTML = `<div class="empty">${message}</div>`;
    return;
  }

  renderBars(
    els.summaryTimeline,
    summary.timeline || [],
    (item) => item.bucket || "unknown",
    (item) => item.count,
    "No timeline data yet."
  );

  const grouped = new Map();
  let legacyCount = 0;
  (summary.model_comparison || []).forEach((row) => {
    const key = row.ai_profile_uid || row.model_identity || "legacy-profile";
    const modelIdentity = row.model_identity || "";
    const isLegacy = key === "legacy-profile" || !modelIdentity || modelIdentity === "unknown model";
    if (isLegacy) {
      legacyCount += Number(row.count || 0);
      return;
    }
    grouped.set(key, (grouped.get(key) || 0) + Number(row.count || 0));
    grouped.set(`${key}:label`, modelIdentity);
  });
  const activeProfile = summary.active_ai_profile;
  if (activeProfile && !grouped.has(activeProfile.uid)) {
    grouped.set(activeProfile.uid, 0);
    grouped.set(`${activeProfile.uid}:label`, `${activeProfile.provider}:${activeProfile.model}`);
  }
  const modelRows = [...grouped.entries()]
    .filter(([key]) => !String(key).endsWith(":label"))
    .map(([key, count]) => ({ key, model: grouped.get(`${key}:label`) || key, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5);
  const modelMax = Math.max(1, ...modelRows.map((item) => Number(item.count || 0)));
  els.summaryModels.innerHTML = `
    <div class="summary-stack">
      ${activeProfile ? `
        <div class="summary-cardline">
          <strong>${escapeHtml(activeProfile.name)}</strong>
          <span>selected</span>
        </div>
        <small>${escapeHtml(activeProfile.uid)} · ${escapeHtml(activeProfile.provider)}:${escapeHtml(activeProfile.model)}</small>
      ` : `<div class="empty">No selected AI profile.</div>`}
      <div class="bar-list compact-bars">
        ${modelRows.map((item) => `
          <div>
            <div class="row tight">
              <strong>${escapeHtml(item.model)}</strong>
              <span>${item.count}</span>
            </div>
            <div class="bar"><span style="--value:${(Number(item.count || 0) / modelMax) * 100}%"></span></div>
            <small>${item.key === "legacy-profile" ? "rows created before AI profiles were enabled" : `profile ${escapeHtml(item.key)}`}</small>
          </div>
        `).join("") || `<div class="empty">No AI reports yet.</div>`}
        ${legacyCount ? `
          <div>
            <div class="row tight">
              <strong>Legacy AI reports</strong>
              <span>${legacyCount}</span>
            </div>
            <small>older rows without profile UID</small>
          </div>
        ` : ""}
      </div>
    </div>
  `;

  const zeek = summary.zeek || {};
  const zeekCounts = zeek.event_counts || {};
  const zeekLogs = zeek.logs || [];
  els.summaryZeek.innerHTML = `
    <div class="summary-stack zeek-summary">
      <div class="summary-cardline">
        <strong>${zeek.running ? "running" : zeek.installed ? "installed" : "unavailable"}</strong>
        <span>${zeek.interface || "no interface"}</span>
      </div>
      <small>${zeek.log_directory || "No Zeek log directory configured"}</small>
      <div class="split-mini-list">
        <div>
          <strong>Events</strong>
          <small>notice ${zeekCounts.notice || 0}</small>
          <small>weird ${zeekCounts.weird || 0}</small>
          <small>conn ${zeekCounts.conn || 0}</small>
        </div>
        <div>
          <strong>Logs</strong>
          ${zeekLogs.slice(0, 10).map((item) => `
            <small>${item.log_type}: ${item.exists ? "ready" : "missing"}</small>
          `).join("") || `<small>No log checks available.</small>`}
        </div>
      </div>
      <small>Community packages: ${(zeek.community_packages || []).length || 0} configured through zkg.</small>
      <a class="telemetry-open-link" href="/zeek" target="_blank" rel="noopener">Open Zeek Telemetry</a>
    </div>
  `;
}

function dashboardFindingGroups(findings) {
  const groups = new Map();
  findings.forEach((finding) => {
    const sensor = String(finding.sensor || "unknown").toLowerCase();
    const name = String(finding.finding_name || finding.finding_type || "Finding");
    const key = `${sensor}|${name.toLowerCase()}`;
    const existing = groups.get(key);
    if (!existing) {
      groups.set(key, {
        sensor,
        name,
        count: 1,
        first: finding,
        last: finding
      });
      return;
    }
    existing.count += 1;
    const timestamp = new Date(finding.finding_timestamp || 0).getTime();
    const firstTimestamp = new Date(existing.first.finding_timestamp || 0).getTime();
    const lastTimestamp = new Date(existing.last.finding_timestamp || 0).getTime();
    if (timestamp < firstTimestamp) existing.first = finding;
    if (timestamp >= lastTimestamp) existing.last = finding;
  });
  return [...groups.values()];
}

function renderAlerts(alerts) {
  els.alerts.innerHTML = alerts.map((alert) => {
    const findings = alert.sensor_findings || [];
    const findingGroups = dashboardFindingGroups(findings);
    const sensors = [...new Set(findings.map((finding) => String(finding.sensor || "unknown").toLowerCase()))];
    const timestamp = alert.timestamp || findings[0]?.finding_timestamp;
    const hasDecision = Boolean(alert.final_classification);
    const primaryName = alert.signature || findingGroups[0]?.name || "Network detection";
    const primaryGroup = findingGroups.find((group) => group.name === primaryName);
    const repeatedCount = Math.max(0, Number(primaryGroup?.count || 1) - 1);
    return `
      <a class="alert unified-alert investigation-link ${sensors.length > 1 ? "multi-sensor-alert" : ""} ${hasDecision ? "" : "pending-assessment"}" href="${alert.detection_id ? investigationUrl(alert.detection_id, alert.case_uid) : "#"}" target="_blank" rel="noopener">
        <div class="alert-time-block">
          <span>Detected</span>
          <time>${escapeHtml(displayTimestamp(timestamp))}</time>
          <small>${escapeHtml(alert.case_uid || alert.event_uid || `#${alert.detection_id || "unlinked"}`)}</small>
        </div>
        <div class="alert-main">
          <div class="sensor-badges">
            ${sensors.map((sensor) => `<span class="sensor-badge ${escapeHtml(sensor)}">${escapeHtml(sensor.toUpperCase())}</span>`).join("") || `<span class="sensor-badge unknown">UNLINKED</span>`}
            <span class="correlation-label">${escapeHtml(detectionLabel(alert.sensor_state || "single_sensor"))}</span>
          </div>
          <strong class="alert-signature">
            ${escapeHtml(primaryName)}
            ${repeatedCount ? `<span class="signature-repeat-count">+${repeatedCount}</span>` : ""}
          </strong>
          <p class="alert-flow">
            ${escapeHtml(alert.src_ip || "unknown")}:${escapeHtml(alert.src_port || "")}
            <span aria-hidden="true">-&gt;</span>
            ${escapeHtml(alert.dest_ip || "unknown")}:${escapeHtml(alert.dest_port || "")}
            ${escapeHtml(alert.protocol || "")}
          </p>
          <div class="sensor-finding-list">
            ${findingGroups.map((group) => `
              <div class="sensor-finding-row">
                <span class="sensor-badge ${escapeHtml(group.sensor)}">${escapeHtml(group.sensor.toUpperCase())}</span>
                <div class="sensor-finding-copy">
                  <strong>${escapeHtml(group.name)}${group.count > 1 ? ` <span class="inline-repeat-count">+${group.count - 1}</span>` : ""}</strong>
                  <span>${group.count} stored event${group.count === 1 ? "" : "s"} · ${escapeHtml(group.first.event_uid || "No event UID")}${group.count > 1 ? ` through ${escapeHtml(group.last.event_uid || "latest event")}` : ""}</span>
                  <time>${escapeHtml(displayTimestamp(group.first.finding_timestamp))}${group.count > 1 ? ` to ${escapeHtml(displayTimestamp(group.last.finding_timestamp))}` : ""}</time>
                </div>
              </div>
            `).join("") || `<small>No linked sensor findings stored.</small>`}
          </div>
        </div>
        ${hasDecision ? `
          <div class="classification-badge ${classificationClass(alert.final_classification)}">
            <span>${escapeHtml(alert.final_classification)}</span>
          </div>
        ` : ""}
      </a>
    `;
  }).join("") || `<div class="empty">No unified detections yet. Start Suricata and Zeek ingestion, then refresh.</div>`;
}

function classificationClass(value) {
  const normalized = String(value || "").toLowerCase();
  if (normalized.includes("dangerous")) return "danger";
  if (normalized.includes("human") || normalized.includes("analyst")) return "review";
  return "safe";
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
  `).join("") || `<div class="empty">No runtime logs yet. Start ingest or check the AI model.</div>`;
}

async function refresh(options = {}) {
  const preserveScroll = Boolean(options.preserveScroll);
  const scrollX = window.scrollX;
  const scrollY = window.scrollY;
  try {
    els.refresh.disabled = true;
    els.refresh.textContent = "Refreshing";
    const summaryRequest = getJson("/api/dashboard-summary?limit=12").catch((error) => ({ _error: error.message }));
    const [summary, alerts, events] = await Promise.all([
      summaryRequest,
      getJson(`/api/latest-alerts?limit=50&sensor=${encodeURIComponent(selectedSensorFilter)}`),
      getJson("/api/events?limit=40")
    ]);
    els.mode.textContent = "analysis";
    renderSummary(summary);
    renderAlerts(alerts);
    renderEvents(events);
    els.updated.textContent = `Updated ${new Date().toLocaleTimeString()}`;
  } catch (error) {
    els.updated.textContent = "Dashboard API error";
    els.alerts.innerHTML = `<div class="empty">${error.message}</div>`;
    els.events.innerHTML = `<div class="empty">${error.message}</div>`;
    els.summaryTimeline.innerHTML = `<div class="empty">${error.message}</div>`;
    els.summaryModels.innerHTML = `<div class="empty">${error.message}</div>`;
    els.summaryZeek.innerHTML = `<div class="empty">${error.message}</div>`;
  } finally {
    els.refresh.disabled = false;
    els.refresh.textContent = "Refresh";
    if (preserveScroll) {
      requestAnimationFrame(() => window.scrollTo(scrollX, scrollY));
    }
  }
}

async function checkAiModel() {
  els.updated.textContent = "Checking AI model";
  try {
    await getJson("/api/ai-status");
  } finally {
    refresh();
  }
}

async function resetLogs() {
  const confirmText = window.prompt("Type RESET to clear dashboard logs, cases, AI reports, reviews, and cached threat intelligence.");
  if (confirmText !== "RESET") return;
  await sendJson("/api/reset-logs", "POST", { confirm: confirmText });
  refresh();
}

function handleDashboardClick(event) {
  const sensorFilterButton = event.target.closest ? event.target.closest("[data-sensor-filter]") : null;
  if (sensorFilterButton) {
    selectedSensorFilter = sensorFilterButton.dataset.sensorFilter || "all";
    document.querySelectorAll("[data-sensor-filter]").forEach((button) => {
      button.classList.toggle("selected", button === sensorFilterButton);
    });
    refresh({ preserveScroll: true });
  }
}

els.refresh.addEventListener("click", refresh);
els.checkAiModel.addEventListener("click", checkAiModel);
els.resetLogs.addEventListener("click", resetLogs);
document.addEventListener("click", handleDashboardClick);
refresh();

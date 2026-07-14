const params = new URLSearchParams(window.location.search);
const ipAddress = params.get("address");

const els = {
  title: document.querySelector("#ip-title"),
  updated: document.querySelector("#ip-updated"),
  alertCount: document.querySelector("#ip-alert-count"),
  detectionCount: document.querySelector("#ip-detection-count"),
  role: document.querySelector("#ip-role"),
  roleDetail: document.querySelector("#ip-role-detail"),
  intelMatchCount: document.querySelector("#ip-intel-match-count"),
  intelProviderCount: document.querySelector("#ip-intel-provider-count"),
  profile: document.querySelector("#ip-profile"),
  peerChart: document.querySelector("#ip-peer-chart"),
  detectionTypes: document.querySelector("#ip-detection-types"),
  outcomes: document.querySelector("#ip-outcomes"),
  detections: document.querySelector("#ip-detections"),
  alerts: document.querySelector("#ip-alerts"),
  intelHistory: document.querySelector("#ip-intel-history")
};

async function getJson(path) {
  const response = await fetch(path, { cache: "no-store" });
  if (!response.ok) throw new Error(`${path} returned ${response.status}`);
  return response.json();
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function label(value) {
  if (!value) return "Unknown";
  return String(value).replaceAll("_", " ").replace(/\b\w/g, (char) => char.toUpperCase());
}

function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

function investigationUrl(detectionId) {
  return `/investigation?id=${encodeURIComponent(detectionId)}`;
}

function ipWorkbookUrl(address) {
  return `/ip?address=${encodeURIComponent(address)}`;
}

function scoreClass(score) {
  const value = Number(score || 0);
  if (value >= 70) return "danger";
  if (value >= 30) return "review";
  return "safe";
}

function scoreBadge(score, badgeLabel = "Score") {
  const value = Number(score || 0);
  return `
    <div class="score-badge ${scoreClass(value)}">
      <span>${escapeHtml(badgeLabel)}</span>
      <strong>${value}</strong>
      <small>/100</small>
    </div>
  `;
}

function renderBars(container, rows, labelFn, valueFn, emptyText) {
  const max = Math.max(1, ...rows.map((row) => Number(valueFn(row) || 0)));
  container.innerHTML = `
    <div class="bar-list">
      ${rows.map((row) => `
        <div>
          <div class="row tight">
            <strong>${escapeHtml(labelFn(row))}</strong>
            <span>${escapeHtml(valueFn(row))}</span>
          </div>
          <div class="bar"><span style="--value:${(Number(valueFn(row) || 0) / max) * 100}%"></span></div>
        </div>
      `).join("") || `<div class="empty">${escapeHtml(emptyText)}</div>`}
    </div>
  `;
}

function renderPeerPie(peers) {
  const top = peers.slice(0, 6);
  const total = top.reduce((sum, item) => sum + Number(item.count || 0), 0);
  if (!total) {
    els.peerChart.innerHTML = `<div class="empty">No connected peers found.</div>`;
    return;
  }

  const colors = [cssVar("--green"), cssVar("--cyan"), cssVar("--amber"), cssVar("--red"), "#a78bfa", "#94a3b8"];
  let cursor = 0;
  const segments = top.map((item, index) => {
    const start = cursor;
    const size = (Number(item.count || 0) / total) * 360;
    cursor += size;
    return `${colors[index]} ${start}deg ${cursor}deg`;
  });

  els.peerChart.innerHTML = `
    <div class="pie-layout dashboard-pie">
      <div class="pie-chart compact-pie" style="background: conic-gradient(${segments.join(", ")});"></div>
      <div class="legend-list compact-legend">
        ${top.map((item, index) => `
          <div>
            <span class="legend-dot" style="background:${colors[index]}"></span>
            <a class="inline-link strong-link" href="${ipWorkbookUrl(item.peer_ip)}" target="_blank" rel="noopener">${escapeHtml(item.peer_ip)}</a>
            <small>${Number(item.count || 0)} detections · ${escapeHtml(item.asset ? item.asset.name : item.location || item.scope || "unknown")}</small>
          </div>
        `).join("")}
      </div>
    </div>
  `;
}

function profileRow(title, body, meta = "") {
  return `
    <div class="workbook-row">
      <strong>${escapeHtml(title)}</strong>
      <p>${escapeHtml(body || "None")}</p>
      ${meta ? `<small>${escapeHtml(meta)}</small>` : ""}
    </div>
  `;
}

function renderProfile(data) {
  const profile = data.profile || {};
  const asset = data.asset;
  const providers = data.threat_intel || [];
  els.profile.innerHTML = [
    profileRow("Local classification", `${profile.location || "unknown"} · ${profile.scope || "unknown"}`, profile.reason || ""),
    profileRow("Registered asset", asset ? `${asset.name} · ${label(asset.device_type)} · score ${asset.asset_score}` : "No registered asset", asset ? `${asset.function || "No function"} · ${asset.network_interface || "unknown interface"}` : "Add this IP in Admin or Asset Inventory if it is an internal machine."),
    ...providers.map((provider) => profileRow(
      provider.label || label(provider.name),
      provider.result === "not_active" ? "Not active" : provider.result === "matched" ? `${provider.match_count} matching indicator${provider.match_count === 1 ? "" : "s"}` : "Active · no match",
      (provider.matches || []).slice(0, 3).map((match) => `${match.category || "indicator"} · confidence ${match.confidence ?? "not supplied"}${match.malware_family ? ` · ${match.malware_family}` : ""}`).join(" | ") || provider.description || ""
    ))
  ].join("");
}

function renderDetections(rows) {
  els.detections.innerHTML = rows.map((row) => `
    <article class="evidence-item">
      <div class="row tight">
        <strong>${escapeHtml(row.final_classification || row.ai_classification || "Detection")}</strong>
        <span>${escapeHtml(row.role || "related")}</span>
      </div>
      ${scoreBadge(row.final_score ?? row.python_initial_score ?? 0, "Final")}
      <div class="evidence-chain">
        <div>
          <span>Alert</span>
          <strong>${escapeHtml(row.signature || "Suricata alert")}</strong>
          <small>${escapeHtml(row.src_ip || "unknown")}:${escapeHtml(row.src_port || "")} -> ${escapeHtml(row.dest_ip || "unknown")}:${escapeHtml(row.dest_port || "")}</small>
        </div>
        <div>
          <span>Detection</span>
          <strong>${escapeHtml(label(row.detection_type))}</strong>
          <small>${Number(row.alert_count || 0)} alerts · ${Number(row.unique_dest_ports || 0)} ports · ${escapeHtml(row.mitre_id || "no MITRE")}</small>
        </div>
        <div>
          <span>AI Model</span>
          <strong>${escapeHtml(row.ai_classification || "No opinion")}</strong>
          <small>${escapeHtml(row.ai_confidence || "No confidence")} · ${escapeHtml(row.ai_model_identity || "unknown model")}</small>
          <small>${escapeHtml(row.ai_reason || "No AI reason stored.")}</small>
        </div>
        <div>
          <span>Analyst</span>
          <strong>${escapeHtml(row.review_status || "No review")}</strong>
          <small>${escapeHtml(row.analyst_action || "No analyst override")}</small>
        </div>
      </div>
      <a class="text-button evidence-open" href="${investigationUrl(row.detection_id)}" target="_blank" rel="noopener">Open Investigation</a>
    </article>
  `).join("") || `<div class="empty">No correlated detections found for this IP.</div>`;
}

function renderAlerts(rows) {
  els.alerts.innerHTML = rows.map((alert) => `
    <div class="workbook-row">
      <strong>${escapeHtml(alert.src_ip || "unknown")} -> ${escapeHtml(alert.dest_ip || "unknown")}</strong>
      <p>${escapeHtml(alert.signature || "Suricata alert")}</p>
      <small>${escapeHtml(alert.timestamp || "unknown time")} · ${escapeHtml(alert.protocol || "")} · priority ${escapeHtml(alert.priority || "unknown")} · ${escapeHtml(label(alert.detection_type))}</small>
      ${alert.detection_id ? `<a class="inline-link" href="${investigationUrl(alert.detection_id)}" target="_blank" rel="noopener">Open Investigation</a>` : ""}
    </div>
  `).join("") || `<div class="empty">No raw alerts found for this IP.</div>`;
}

function renderIntelHistory(rows, providers) {
  els.intelHistory.innerHTML = (providers || []).map((provider) => `
    <div class="workbook-row">
      <strong>${escapeHtml(provider.label || label(provider.name))}</strong>
      <p>${provider.result === "not_active" ? "Not active" : provider.result === "matched" ? `${provider.match_count} match${provider.match_count === 1 ? "" : "es"}` : "Active · no match"}</p>
      <small>${escapeHtml(provider.last_success ? `Feed updated ${provider.last_success}` : provider.description || "No feed refresh recorded")}</small>
    </div>
  `).join("") + rows.map((row) => `
    <div class="workbook-row">
      <strong>${escapeHtml(row.source || "source")} · ${escapeHtml(row.reputation || "unknown")}</strong>
      <p>${escapeHtml(row.lookup_result || "No detail")}</p>
      <small>malicious ${Number(row.malicious_count || 0)} · suspicious ${Number(row.suspicious_count || 0)} · ${escapeHtml(row.lookup_time || "unknown time")}</small>
    </div>
  `).join("");
}

function render(data) {
  const summary = data.summary || {};
  const sourceCount = Number(summary.source_detection_count || 0);
  const destinationCount = Number(summary.destination_detection_count || 0);
  let role = "Mixed";
  if (sourceCount > destinationCount) role = "Source";
  if (destinationCount > sourceCount) role = "Destination";
  if (!sourceCount && !destinationCount) role = "Unknown";

  els.title.textContent = data.ip_address || ipAddress || "IP Detail";
  els.alertCount.textContent = summary.alert_count || 0;
  els.detectionCount.textContent = summary.detection_count || 0;
  els.role.textContent = role;
  els.roleDetail.textContent = `${sourceCount} source detections · ${destinationCount} destination detections`;
  const providers = data.threat_intel || [];
  const activeProviders = providers.filter((provider) => provider.enabled);
  const matchCount = providers.reduce((sum, provider) => sum + Number(provider.match_count || 0), 0);
  els.intelMatchCount.textContent = matchCount;
  els.intelProviderCount.textContent = `${activeProviders.length} active provider${activeProviders.length === 1 ? "" : "s"}`;

  renderProfile(data);
  renderPeerPie(data.peers || []);
  renderBars(
    els.detectionTypes,
    data.detection_types || [],
    (row) => label(row.detection_type),
    (row) => row.count,
    "No detection types found."
  );
  renderBars(
    els.outcomes,
    data.outcomes || [],
    (row) => row.final_classification || "No decision",
    (row) => row.count,
    "No response outcomes found."
  );
  renderDetections(data.detections || []);
  renderAlerts(data.alerts || []);
  renderIntelHistory(data.intel_history || [], providers);
  els.updated.textContent = new Date().toLocaleTimeString();
}

async function refresh() {
  if (!ipAddress) {
    els.updated.textContent = "Missing IP address";
    els.profile.innerHTML = `<div class="empty">Open this page from an IP address, detection workbook, or investigation.</div>`;
    return;
  }
  try {
    render(await getJson(`/api/ip-detail?address=${encodeURIComponent(ipAddress)}&limit=100`));
  } catch (error) {
    els.updated.textContent = "IP API error";
    els.profile.innerHTML = `<div class="empty">${escapeHtml(error.message)}</div>`;
  }
}

refresh();

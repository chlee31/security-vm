const els = {
  updated: document.querySelector("#asset-updated"),
  total: document.querySelector("#asset-total"),
  highValue: document.querySelector("#asset-high-value"),
  ens37: document.querySelector("#asset-ens37"),
  interfaceLabel: document.querySelector("#asset-interface-label"),
  matches: document.querySelector("#asset-matches"),
  typeChart: document.querySelector("#asset-type-chart"),
  scoreChart: document.querySelector("#asset-score-chart"),
  records: document.querySelector("#asset-records"),
  search: document.querySelector("#asset-search"),
  statusFilter: document.querySelector("#asset-status-filter")
};

let currentPayload = { assets: [], types: [], summary: {} };

async function getJson(path) {
  const response = await fetch(path, { cache: "no-store" });
  if (!response.ok) throw new Error(`${path} returned ${response.status}`);
  return response.json();
}

function label(value) {
  if (!value) return "Unknown";
  return String(value).replaceAll("_", " ").replace(/\b\w/g, (char) => char.toUpperCase());
}

function scoreClass(score) {
  const value = Number(score || 0);
  if (value >= 8) return "danger";
  if (value >= 6) return "review";
  return "safe";
}

function investigationUrl(detectionId) {
  return `/investigation?id=${encodeURIComponent(detectionId)}`;
}

function countActiveMatches(assets) {
  return assets
    .filter((asset) => asset.status === "active")
    .reduce((total, asset) => total + Number(asset.matches?.total_matches || 0), 0);
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

function renderTypeChart(payload) {
  const rows = (payload.by_type || []).map((row) => ({
    name: `${label(row.device_type)} ${row.status === "inactive" ? "(inactive)" : ""}`.trim(),
    count: row.count,
    avg_score: row.avg_score
  }));
  renderBars(els.typeChart, rows, (row) => row.name, (row) => row.count, "No asset types registered yet.");
}

function renderScoreChart(payload) {
  const rows = payload.by_score || [];
  renderBars(els.scoreChart, rows, (row) => `Score ${row.asset_score}`, (row) => row.count, "No active asset scores yet.");
}

function renderRecentDetections(asset) {
  const rows = asset.recent_detections || [];
  if (!rows.length) return `<div class="empty">No matching detections for this registered IP yet.</div>`;
  return `
    <div class="mini-list dense asset-match-list">
      ${rows.map((row) => `
        <div>
          <strong>${label(row.detection_type)} #${row.detection_id}</strong>
          <small>${row.src_ip || "unknown"} -> ${row.dest_ip || "unknown"} · score ${row.final_score ?? row.python_initial_score ?? 0}</small>
          <small>${row.signature || row.final_classification || "Detection evidence"}</small>
          <a class="inline-link" href="${investigationUrl(row.detection_id)}" target="_blank" rel="noopener">Open Investigation</a>
        </div>
      `).join("")}
    </div>
  `;
}

function assetSearchText(asset) {
  return [
    asset.name,
    asset.ip_address,
    asset.device_type,
    asset.network_interface,
    asset.function,
    asset.notes,
    asset.status
  ].join(" ").toLowerCase();
}

function filteredAssets() {
  const status = els.statusFilter.value;
  const query = els.search.value.trim().toLowerCase();
  return (currentPayload.assets || []).filter((asset) => {
    const statusOk = status === "all" || asset.status === status;
    const queryOk = !query || assetSearchText(asset).includes(query);
    return statusOk && queryOk;
  });
}

function renderRecords() {
  const assets = filteredAssets();
  const defaultInterface = currentPayload.default_interface || "ens37";
  els.records.innerHTML = assets.map((asset) => `
    <article class="asset-workbook-item ${asset.status === "inactive" ? "inactive" : "active"}">
      <div class="asset-record-main">
        <div>
          <div class="row tight">
            <strong>${asset.name}</strong>
            <span class="status-pill ${asset.status === "inactive" ? "inactive" : "active"}">${asset.status}</span>
          </div>
          <p>${asset.ip_address} · ${label(asset.device_type)} · ${asset.network_interface || defaultInterface}</p>
          <small>${asset.function || "No machine function recorded"}</small>
          ${asset.notes ? `<small>${asset.notes}</small>` : `<small>No analyst notes recorded.</small>`}
          <small>Created ${asset.created_at || "unknown"} · updated ${asset.updated_at || "unknown"}</small>
        </div>
        <div class="score-badge ${scoreClass(asset.asset_score)}">
          <span>Asset</span>
          <strong>${asset.asset_score}</strong>
          <small>/10</small>
        </div>
      </div>
      <div class="asset-context-grid">
        <div>
          <span>Decision Context</span>
          <strong>${Number(asset.matches?.total_matches || 0)} matched detections</strong>
          <small>Source ${asset.matches?.source_matches || 0} · destination ${asset.matches?.destination_matches || 0}</small>
        </div>
        <div>
          <span>AI Context</span>
          <strong>${asset.status === "active" ? "Sent when IP matches" : "Inactive"}</strong>
          <small>Python adds the asset score before asking the AI model for review.</small>
        </div>
      </div>
      ${renderRecentDetections(asset)}
    </article>
  `).join("") || `<div class="empty">No assets match this filter.</div>`;
}

function render(payload) {
  currentPayload = payload;
  const summary = payload.summary || {};
  const assets = payload.assets || [];
  const active = assets.filter((asset) => asset.status === "active");
  els.total.textContent = summary.total || active.length || 0;
  els.highValue.textContent = summary.high_value || 0;
  els.ens37.textContent = summary.ens37 || 0;
  els.interfaceLabel.textContent = `${payload.default_interface || "ens37"} target`;
  els.matches.textContent = countActiveMatches(assets);
  renderTypeChart(payload);
  renderScoreChart(payload);
  renderRecords();
  els.updated.textContent = new Date().toLocaleTimeString();
}

async function refresh() {
  try {
    render(await getJson("/api/assets-workbook?limit=500"));
  } catch (error) {
    els.updated.textContent = "Asset API error";
    els.records.innerHTML = `<div class="empty">${error.message}</div>`;
  }
}

els.search.addEventListener("input", renderRecords);
els.statusFilter.addEventListener("change", renderRecords);
refresh();
setInterval(refresh, 5000);

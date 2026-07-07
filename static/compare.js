const els = {
  updated: document.querySelector("#compare-updated"),
  models: document.querySelector("#cmp-models"),
  reports: document.querySelector("#cmp-reports"),
  adjust: document.querySelector("#cmp-adjust"),
  time: document.querySelector("#cmp-time"),
  modelsList: document.querySelector("#cmp-models-list"),
  recent: document.querySelector("#cmp-recent")
};

async function getJson(path) {
  const response = await fetch(path, { cache: "no-store" });
  if (!response.ok) throw new Error(`${path} returned ${response.status}`);
  return response.json();
}

function investigationUrl(detectionId) {
  return `/investigation?id=${encodeURIComponent(detectionId)}`;
}

function classificationClass(value) {
  const normalized = String(value || "").toLowerCase();
  if (normalized.includes("dangerous")) return "danger";
  if (normalized.includes("human")) return "review";
  return "safe";
}

function groupComparison(rows) {
  const grouped = new Map();
  rows.forEach((row) => {
    const key = row.ai_profile_uid || row.model_identity || "unknown model";
    const modelIdentity = row.model_identity || "";
    const isLegacy = key === "legacy-profile" || !modelIdentity || modelIdentity === "unknown model";
    if (!grouped.has(key)) {
      grouped.set(key, {
        uid: row.ai_profile_uid || "legacy-profile",
        model: isLegacy ? "Legacy AI reports" : modelIdentity,
        provider: row.model_provider || "unknown",
        total: 0,
        weightedAdjust: 0,
        weightedMs: 0,
        classifications: []
      });
    }
    const item = grouped.get(key);
    const count = Number(row.count || 0);
    item.total += count;
    item.weightedAdjust += Number(row.avg_risk_adjustment || 0) * count;
    item.weightedMs += Number(row.avg_elapsed_ms || 0) * count;
    item.classifications.push(row);
  });
  return [...grouped.values()].sort((a, b) => b.total - a.total);
}

function renderComparison(rows) {
  const groups = groupComparison(rows);
  const totalReports = groups.reduce((sum, item) => sum + item.total, 0);
  const weightedAdjust = groups.reduce((sum, item) => sum + item.weightedAdjust, 0);
  const weightedMs = groups.reduce((sum, item) => sum + item.weightedMs, 0);
  els.models.textContent = groups.length;
  els.reports.textContent = totalReports;
  els.adjust.textContent = totalReports ? Math.round(weightedAdjust / totalReports) : 0;
  els.time.textContent = totalReports ? Math.round(weightedMs / totalReports) : 0;

  els.modelsList.innerHTML = groups.map((item) => {
    const max = Math.max(1, ...item.classifications.map((row) => row.count));
    return `
      <div class="workbook-row">
        <div class="row tight">
          <strong>${item.model}</strong>
          <span>${item.total} reports</span>
        </div>
        <p>${item.provider} · UID ${item.uid}</p>
        <div class="bar-list compact-bars">
          ${item.classifications.map((row) => `
            <div>
              <div class="row tight">
                <strong>${row.classification}</strong>
                <span>${row.count}</span>
              </div>
              <div class="bar"><span style="--value:${(row.count / max) * 100}%"></span></div>
              <small>avg adjustment ${Math.round(row.avg_risk_adjustment || 0)} · avg ${Math.round(row.avg_elapsed_ms || 0)}ms</small>
            </div>
          `).join("")}
        </div>
      </div>
    `;
  }).join("") || `<div class="empty">No model comparison data yet.</div>`;
}

function renderRecent(reports) {
  els.recent.innerHTML = reports.map((report) => `
    <a class="alert ai-opinion investigation-link ${classificationClass(report.classification)}" href="${report.detection_id ? investigationUrl(report.detection_id) : "#"}" target="_blank" rel="noopener">
      <time>${report.created_at || report.timestamp || ""}</time>
      <div>
        <div class="row tight">
          <strong>${report.classification || "AI opinion"}</strong>
          <span>${report.model_identity || "unknown model"}</span>
        </div>
        <p>${report.src_ip || "unknown"} -> ${report.dest_ip || "unknown"} ${report.signature || ""}</p>
        <p>${report.reason || "No reason returned."}</p>
        <p>Profile ${report.ai_profile_uid || "legacy-profile"} · run ${report.model_run_id || "not recorded"} · adjust ${report.risk_adjustment ?? 0} · ${report.elapsed_ms ?? 0}ms</p>
      </div>
    </a>
  `).join("") || `<div class="empty">No recent AI opinions yet.</div>`;
}

async function refresh() {
  try {
    const [comparison, reports] = await Promise.all([
      getJson("/api/ai-model-comparison"),
      getJson("/api/ai-opinions?limit=100")
    ]);
    renderComparison(comparison);
    renderRecent(reports);
    els.updated.textContent = new Date().toLocaleTimeString();
  } catch (error) {
    els.updated.textContent = "Compare API error";
    els.modelsList.innerHTML = `<div class="empty">${error.message}</div>`;
    els.recent.innerHTML = `<div class="empty">${error.message}</div>`;
  }
}

refresh();
setInterval(refresh, 5000);

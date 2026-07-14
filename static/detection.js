const params = new URLSearchParams(window.location.search);
const detectionType = params.get("type") || "unknown";

const els = {
  title: document.querySelector("#workbook-title"),
  updated: document.querySelector("#workbook-updated"),
  total: document.querySelector("#wb-total"),
  avgScore: document.querySelector("#wb-avg-score"),
  maxScore: document.querySelector("#wb-max-score"),
  publicIps: document.querySelector("#wb-public-ips"),
  ipPie: document.querySelector("#wb-ip-pie"),
  aiChart: document.querySelector("#wb-ai-chart"),
  timeline: document.querySelector("#wb-timeline"),
  ips: document.querySelector("#wb-ips"),
  recent: document.querySelector("#wb-recent"),
  evidence: document.querySelector("#wb-evidence")
};

async function getJson(path) {
  const response = await fetch(path, { cache: "no-store" });
  if (!response.ok) throw new Error(`${path} returned ${response.status}`);
  return response.json();
}

function label(value) {
  if (!value) return "Unknown";
  return value.replaceAll("_", " ").replace(/\b\w/g, (char) => char.toUpperCase());
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
      <span>${badgeLabel}</span>
      <strong>${value}</strong>
      <small>/100</small>
    </div>
  `;
}

function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

function investigationUrl(detectionId) {
  return `/investigation?id=${encodeURIComponent(detectionId)}`;
}

function renderPie(ips) {
  const top = ips.slice(0, 6);
  const total = top.reduce((sum, item) => sum + Number(item.count || 0), 0);
  if (!total) {
    els.ipPie.innerHTML = `<div class="empty">No IP connectivity data.</div>`;
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

  els.ipPie.innerHTML = `
    <div class="pie-layout">
      <div class="pie-chart" style="background: conic-gradient(${segments.join(", ")});"></div>
      <div class="legend-list">
        ${top.map((item, index) => `
          <div>
            <span class="legend-dot" style="background:${colors[index]}"></span>
            <strong>${item.ip_address}</strong>
            <small>${item.count} seen · ${item.scope}</small>
          </div>
        `).join("")}
      </div>
    </div>
  `;
}

function renderAiModelChart(evidence) {
  const counts = { Safe: 0, "Human Review Required": 0, Dangerous: 0, "No opinion": 0 };
  evidence.forEach((row) => {
    const classification = row.ai_classification || "No opinion";
    if (classification.toLowerCase().includes("safe")) counts.Safe += 1;
    else if (classification.toLowerCase().includes("danger")) counts.Dangerous += 1;
    else if (classification.toLowerCase().includes("human")) counts["Human Review Required"] += 1;
    else counts["No opinion"] += 1;
  });
  const max = Math.max(1, ...Object.values(counts));

  els.aiChart.innerHTML = `
    <div class="bar-list">
      ${Object.entries(counts).map(([name, count]) => `
        <div>
          <div class="row tight">
            <strong>${name}</strong>
            <span>${count}</span>
          </div>
          <div class="bar"><span style="--value:${(count / max) * 100}%"></span></div>
        </div>
      `).join("")}
    </div>
  `;
}

function renderTimeline(timeline) {
  const max = Math.max(1, ...timeline.map((item) => item.count));
  els.timeline.innerHTML = `
    <div class="timeline workbook-timeline">
      ${timeline.map((item) => `
        <div class="timeline-row">
          <time>${item.bucket || "unknown"}</time>
          <div class="bar"><span style="--value:${(item.count / max) * 100}%"></span></div>
          <strong>${item.count}</strong>
        </div>
      `).join("") || `<div class="empty">No timeline data.</div>`}
    </div>
  `;
}

function renderIps(ips) {
  els.publicIps.textContent = ips.filter((item) => item.scope === "public").length;
  els.ips.innerHTML = ips.map((item) => `
    <div class="workbook-row">
      <div>
        <strong>${item.ip_address}</strong>
        <p>${item.asset ? `${item.asset.name} · ${label(item.asset.device_type)} · score ${item.asset.asset_score}` : item.location}</p>
        <small>${item.scope} · seen ${item.count}</small>
      </div>
    </div>
  `).join("") || `<div class="empty">No IPs found for this detection.</div>`;
}

function renderRecent(recent) {
  els.recent.innerHTML = recent.map((item) => `
    <div class="workbook-row score-row">
      ${scoreBadge(item.python_initial_score || 0, "Score")}
      <div>
        <strong>${item.src_ip || "unknown"} -> ${item.dest_ip || "unknown"}</strong>
        <p>${item.signature || "Detection"}</p>
        <small>${item.ai_classification || "no AI opinion"} · ${item.ai_model_identity || "unknown model"}${item.ai_profile_uid ? ` · profile ${item.ai_profile_uid}` : ""}${item.mitre_id ? ` · ${item.mitre_id}` : ""}</small>
        <a class="inline-link" href="${investigationUrl(item.detection_id)}" target="_blank" rel="noopener">Open Investigation</a>
      </div>
    </div>
  `).join("") || `<div class="empty">No recent detections.</div>`;
}

function renderEvidence(rows) {
  els.evidence.innerHTML = rows.map((row) => `
    <article class="evidence-item">
      <div class="row tight">
        <strong>${row.final_classification || "Decision"}</strong>
        <span>${row.final_action || "none"}</span>
      </div>
      ${scoreBadge(row.final_score ?? 0, "Final")}
      <div class="evidence-chain">
        <div>
          <span>Alert</span>
          <strong>${row.signature || "Suricata alert"}</strong>
          <small>${row.src_ip || "unknown"}:${row.src_port || ""} -> ${row.dest_ip || "unknown"}:${row.dest_port || ""}</small>
        </div>
        <div>
          <span>Correlation</span>
          <strong>${label(row.detection_type)}</strong>
          <small>${row.alert_count || 0} alerts · ${row.unique_dest_ports || 0} ports · ${row.mitre_id || "no MITRE"}</small>
        </div>
        <div>
          <span>AI Model</span>
          <strong>${row.ai_classification || "No opinion"}</strong>
          <small>${row.ai_model_identity || "unknown model"} · profile ${row.ai_profile_uid || "legacy-profile"} · run ${row.ai_model_run_id || "not recorded"}</small>
          <small>${row.ai_reason || "No AI reason stored."}</small>
        </div>
        <div>
          <span>Analyst</span>
          <strong>${row.review_status || "No review"}</strong>
          <small>${row.analyst_action || "No analyst override"}</small>
        </div>
      </div>
      <a class="text-button evidence-open" href="${investigationUrl(row.detection_id)}" target="_blank" rel="noopener">Open Investigation</a>
    </article>
  `).join("") || `<div class="empty">No decision evidence yet.</div>`;
}

async function refresh() {
  els.title.textContent = label(detectionType);
  const encoded = encodeURIComponent(detectionType);
  try {
    const [detail, evidence] = await Promise.all([
      getJson(`/api/detection-detail?detection_type=${encoded}&limit=100`),
      getJson(`/api/decision-evidence?detection_type=${encoded}&limit=100`)
    ]);

    const summary = detail.summary || {};
    els.total.textContent = summary.total || 0;
    els.avgScore.textContent = Math.round(summary.avg_score || 0);
    els.maxScore.textContent = summary.max_score || 0;
    renderPie(detail.ips || []);
    renderAiModelChart(evidence || []);
    renderTimeline(detail.timeline || []);
    renderIps(detail.ips || []);
    renderRecent(detail.recent || []);
    renderEvidence(evidence || []);
    els.updated.textContent = new Date().toLocaleTimeString();
  } catch (error) {
    els.updated.textContent = "Workbook API error";
    els.ipPie.innerHTML = `<div class="empty">${error.message}</div>`;
  }
}

refresh();
setInterval(refresh, 5000);

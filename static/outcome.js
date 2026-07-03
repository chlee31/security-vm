const params = new URLSearchParams(window.location.search);
const outcomeType = params.get("type") || "all";
const detectionType = params.get("detection_type") || "";

const els = {
  title: document.querySelector("#outcome-title"),
  updated: document.querySelector("#outcome-updated"),
  total: document.querySelector("#oc-total"),
  ips: document.querySelector("#oc-ips"),
  maxScore: document.querySelector("#oc-max-score"),
  reviewCount: document.querySelector("#oc-review-count"),
  ipPie: document.querySelector("#oc-ip-pie"),
  detectionChart: document.querySelector("#oc-detection-chart"),
  ollamaChart: document.querySelector("#oc-ollama-chart"),
  reviewChart: document.querySelector("#oc-review-chart"),
  ipsList: document.querySelector("#oc-ips-list"),
  evidence: document.querySelector("#oc-evidence")
};

let currentRows = [];

async function getJson(path) {
  const response = await fetch(path, { cache: "no-store" });
  if (!response.ok) throw new Error(`${path} returned ${response.status}`);
  return response.json();
}

function label(value) {
  if (!value) return "Unknown";
  if (value === "all") return "All Outcomes";
  if (value === "human_review") return "Human Review Required";
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

function countBy(rows, valueFn) {
  const counts = new Map();
  rows.forEach((row) => {
    const values = valueFn(row);
    (Array.isArray(values) ? values : [values]).filter(Boolean).forEach((value) => {
      counts.set(value, (counts.get(value) || 0) + 1);
    });
  });
  return [...counts.entries()]
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count);
}

function renderHorizontalBars(container, rows, emptyText) {
  const max = Math.max(1, ...rows.map((row) => row.count));
  container.innerHTML = `
    <div class="bar-list">
      ${rows.map((row) => `
        <div>
          <div class="row tight">
            <strong>${label(row.name)}</strong>
            <span>${row.count}</span>
          </div>
          <div class="bar"><span style="--value:${(row.count / max) * 100}%"></span></div>
        </div>
      `).join("") || `<div class="empty">${emptyText}</div>`}
    </div>
  `;
}

function renderPie(container, rows, emptyText) {
  const top = rows.slice(0, 6);
  const total = top.reduce((sum, item) => sum + Number(item.count || 0), 0);
  if (!total) {
    container.innerHTML = `<div class="empty">${emptyText}</div>`;
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

  container.innerHTML = `
    <div class="pie-layout">
      <div class="pie-chart" style="background: conic-gradient(${segments.join(", ")});"></div>
      <div class="legend-list">
        ${top.map((item, index) => `
          <div>
            <span class="legend-dot" style="background:${colors[index]}"></span>
            <strong>${item.name}</strong>
            <small>${item.count} matching rows</small>
          </div>
        `).join("")}
      </div>
    </div>
  `;
}

function investigationUrl(detectionId) {
  return `/investigation?id=${encodeURIComponent(detectionId)}`;
}

function renderIpList(rows) {
  const ipCounts = countBy(rows, (row) => [row.src_ip, row.dest_ip]);
  els.ips.textContent = ipCounts.length;
  els.ipsList.innerHTML = ipCounts.map((item) => `
    <div class="workbook-row">
      <div>
        <strong>${item.name}</strong>
        <p>${item.count} matching source/destination appearances</p>
        <small>${label(outcomeType)}${detectionType ? ` · ${label(detectionType)}` : ""}</small>
      </div>
    </div>
  `).join("") || `<div class="empty">No IPs found for this outcome.</div>`;
  renderPie(els.ipPie, ipCounts, "No IP data for this outcome.");
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
          <span>Detection</span>
          <strong>${label(row.detection_type)}</strong>
          <small>${row.alert_count || 0} alerts · ${row.unique_dest_ports || 0} ports · ${row.mitre_id || "no MITRE"}</small>
        </div>
        <div>
          <span>AI Model</span>
          <strong>${row.ollama_classification || "No opinion"}</strong>
          <small>${row.ollama_model_identity || "unknown model"} · profile ${row.ollama_ai_profile_uid || "legacy-profile"} · run ${row.ollama_model_run_id || "not recorded"}</small>
          <small>${row.ollama_reason || "No AI reason stored."}</small>
        </div>
        <div>
          <span>Analyst</span>
          <strong>${row.review_status || "No review"}</strong>
          <small>${row.analyst_action || "No analyst override"}</small>
        </div>
      </div>
      <a class="text-button evidence-open" href="${investigationUrl(row.detection_id)}" target="_blank" rel="noopener">Investigate / Give Feedback</a>
    </article>
  `).join("") || `<div class="empty">No matching decisions.</div>`;
}

async function refresh() {
  const outcomeLabel = label(outcomeType);
  const detectionLabel = detectionType ? ` · ${label(detectionType)}` : "";
  els.title.textContent = `${outcomeLabel}${detectionLabel}`;

  const query = new URLSearchParams({ limit: "200" });
  if (outcomeType !== "all") query.set("outcome", outcomeType);
  if (detectionType) query.set("detection_type", detectionType);

  try {
    const rows = await getJson(`/api/decision-evidence?${query.toString()}`);
    currentRows = rows;
    els.total.textContent = rows.length;
    els.maxScore.textContent = rows.reduce((max, row) => Math.max(max, Number(row.final_score || 0)), 0);
    els.reviewCount.textContent = rows.filter((row) => {
      const text = `${row.final_classification || ""} ${row.final_action || ""} ${row.review_status || ""}`.toLowerCase();
      return text.includes("human") || text.includes("review") || text.includes("pending");
    }).length;

    renderIpList(rows);
    renderHorizontalBars(els.detectionChart, countBy(rows, (row) => row.detection_type || "unknown"), "No detection type data.");
    renderHorizontalBars(els.ollamaChart, countBy(rows, (row) => row.ollama_classification || "No opinion"), "No AI opinion data.");
    renderHorizontalBars(els.reviewChart, countBy(rows, (row) => row.review_status || "No review"), "No analyst review data.");
    renderEvidence(rows);
    els.updated.textContent = new Date().toLocaleTimeString();
  } catch (error) {
    els.updated.textContent = "Outcome API error";
    els.evidence.innerHTML = `<div class="empty">${error.message}</div>`;
  }
}

refresh();
setInterval(refresh, 5000);

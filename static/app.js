const els = {
  totalAlerts: document.querySelector("#total-alerts"),
  totalDetections: document.querySelector("#total-detections"),
  safeCount: document.querySelector("#safe-count"),
  reviewCount: document.querySelector("#review-count"),
  highRiskCount: document.querySelector("#high-risk-count"),
  dangerCount: document.querySelector("#danger-count"),
  totalAssets: document.querySelector("#total-assets"),
  topDetection: document.querySelector("#top-detection"),
  systemMode: document.querySelector("#system-mode"),
  zeekNoticeCount: document.querySelector("#zeek-notice-count"),
  zeekWeirdCount: document.querySelector("#zeek-weird-count"),
  investigationsReady: document.querySelector("#investigations-ready"),
  summaryIpPie: document.querySelector("#summary-ip-pie"),
  summaryTimeline: document.querySelector("#summary-timeline"),
  summaryModels: document.querySelector("#summary-models"),
  summaryEncrypted: document.querySelector("#summary-encrypted"),
  summaryZeek: document.querySelector("#summary-zeek"),
  decisionEvidence: document.querySelector("#decision-evidence"),
  mode: document.querySelector("#mode"),
  updated: document.querySelector("#updated"),
  alerts: document.querySelector("#alerts"),
  aiReports: document.querySelector("#ai-opinions"),
  detections: document.querySelector("#detections"),
  allowlist: document.querySelector("#allowlist"),
  allowlistForm: document.querySelector("#allowlist-form"),
  assets: document.querySelector("#assets"),
  assetForm: document.querySelector("#asset-form"),
  assetType: document.querySelector("#asset-type"),
  assetInterface: document.querySelector("#asset-interface"),
  assetScore: document.querySelector("#asset-score"),
  events: document.querySelector("#events"),
  checkAiModel: document.querySelector("#check-ai-model"),
  resetLogs: document.querySelector("#reset-logs"),
  refresh: document.querySelector("#refresh")
};

let selectedDetectionType = null;
let selectedOutcome = null;
let selectedSensorFilter = "all";

function readHashFilters() {
  const params = new URLSearchParams(window.location.hash.replace(/^#/, ""));
  selectedDetectionType = params.get("type");
  selectedOutcome = params.get("outcome");
}

function writeHashFilters() {
  const params = new URLSearchParams();
  if (selectedDetectionType) params.set("type", selectedDetectionType);
  if (selectedOutcome) params.set("outcome", selectedOutcome);
  const hash = params.toString();
  if (hash) {
    window.location.hash = hash;
  } else {
    history.replaceState(null, "", window.location.pathname);
  }
}

function filteredDashboardUrl(outcome) {
  const params = new URLSearchParams();
  if (selectedDetectionType) params.set("type", selectedDetectionType);
  if (outcome) params.set("outcome", outcome);
  const hash = params.toString();
  return `${window.location.pathname}${hash ? `#${hash}` : ""}`;
}

function detectionWorkbookUrl(detectionType) {
  return `/detection?type=${encodeURIComponent(detectionType)}`;
}

function outcomeWorkbookUrl(outcome) {
  const params = new URLSearchParams();
  if (outcome) params.set("type", outcome);
  if (selectedDetectionType) params.set("detection_type", selectedDetectionType);
  return `/outcome?${params.toString()}`;
}

function assetInventoryUrl() {
  return "/asset-inventory";
}

function investigationUrl(detectionId, caseUid = "") {
  return caseUid
    ? `/investigation?case=${encodeURIComponent(caseUid)}`
    : `/investigation?id=${encodeURIComponent(detectionId)}`;
}

function ipWorkbookUrl(ipAddress) {
  return `/ip?address=${encodeURIComponent(ipAddress)}`;
}

readHashFilters();

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

function scoreClass(score) {
  const value = Number(score || 0);
  if (value >= 70) return "danger";
  if (value >= 30) return "review";
  return "safe";
}

function scoreBadge(score, label = "Score") {
  const value = Number(score || 0);
  return `
    <div class="score-badge ${scoreClass(value)}">
      <span>${label}</span>
      <strong>${value}</strong>
      <small>/100</small>
    </div>
  `;
}

function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

function renderPie(container, rows, labelFn, valueFn, emptyText) {
  const top = rows.slice(0, 6);
  const total = top.reduce((sum, item) => sum + Number(valueFn(item) || 0), 0);
  if (!total) {
    container.innerHTML = `<div class="empty">${emptyText}</div>`;
    return;
  }

  const colors = [cssVar("--green"), cssVar("--cyan"), cssVar("--amber"), cssVar("--red"), "#a78bfa", "#94a3b8"];
  let cursor = 0;
  const segments = top.map((item, index) => {
    const start = cursor;
    const size = (Number(valueFn(item) || 0) / total) * 360;
    cursor += size;
    return `${colors[index]} ${start}deg ${cursor}deg`;
  });

  container.innerHTML = `
    <div class="pie-layout dashboard-pie">
      <div class="pie-chart compact-pie" style="background: conic-gradient(${segments.join(", ")});"></div>
      <div class="legend-list compact-legend">
        ${top.map((item, index) => `
          <div>
            <span class="legend-dot" style="background:${colors[index]}"></span>
            <a class="inline-link strong-link" href="${ipWorkbookUrl(labelFn(item))}" target="_blank" rel="noopener">${labelFn(item)}</a>
            <small>${valueFn(item)} seen</small>
          </div>
        `).join("")}
      </div>
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
    els.summaryIpPie.innerHTML = `<div class="empty">${message}</div>`;
    els.summaryTimeline.innerHTML = `<div class="empty">${message}</div>`;
    els.summaryModels.innerHTML = `<div class="empty">${message}</div>`;
    els.summaryEncrypted.innerHTML = `<div class="empty">${message}</div>`;
    els.summaryZeek.innerHTML = `<div class="empty">${message}</div>`;
    return;
  }

  renderPie(
    els.summaryIpPie,
    summary.top_ips || [],
    (item) => item.ip_address,
    (item) => item.count,
    "No IP activity yet."
  );
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
    const label = modelIdentity;
    grouped.set(key, (grouped.get(key) || 0) + Number(row.count || 0));
    grouped.set(`${key}:label`, label);
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
          <strong>${activeProfile.name}</strong>
          <span>selected</span>
        </div>
        <small>${activeProfile.uid} · ${activeProfile.provider}:${activeProfile.model}</small>
      ` : `<div class="empty">No selected AI profile.</div>`}
      <div class="bar-list compact-bars">
        ${modelRows.map((item) => `
          <div>
            <div class="row tight">
              <strong>${item.model}</strong>
              <span>${item.count}</span>
            </div>
            <div class="bar"><span style="--value:${(Number(item.count || 0) / modelMax) * 100}%"></span></div>
            <small>${item.key === "legacy-profile" ? "rows created before AI profiles were enabled" : `profile ${item.key}`}</small>
          </div>
        `).join("") || `<div class="empty">No AI reports yet.</div>`}
        ${legacyCount ? `
          <div>
            <div class="row tight">
              <strong>Legacy AI reports</strong>
              <span>${legacyCount}</span>
            </div>
            <small>older rows without profile UID; restart ingest for new named rows</small>
          </div>
        ` : ""}
      </div>
    </div>
  `;

  const encrypted = summary.encrypted_traffic || {};
  const portRows = encrypted.ports || [];
  const ipRows = encrypted.ips || [];
  els.summaryEncrypted.innerHTML = `
    <div class="summary-stack encrypted-summary">
      <div class="summary-cardline">
        <strong>${encrypted.candidate_count || 0} candidates</strong>
        <span>metadata only</span>
      </div>
      <small>${encrypted.not_visible || "Encrypted payload contents are not visible."}</small>
      <div class="mini-list dense">
        <div>
          <strong>Visible signals</strong>
          <small>${(encrypted.visible || []).join(" · ") || "IPs · ports · timing · reputation"}</small>
        </div>
      </div>
      <div class="split-mini-list">
        <div>
          <strong>Top ports</strong>
          ${(portRows.slice(0, 4).map((item) => `
            <small>${item.protocol || "unknown"}/${item.port || "unknown"} · ${item.count || 0}</small>
          `).join("")) || `<small>No encrypted candidates yet.</small>`}
        </div>
        <div>
          <strong>Top IPs</strong>
          ${(ipRows.slice(0, 4).map((item) => `
            <small><a class="inline-link" href="${ipWorkbookUrl(item.ip_address)}" target="_blank" rel="noopener">${item.ip_address}</a> · ${item.count || 0}</small>
          `).join("")) || `<small>No IPs yet.</small>`}
        </div>
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
          ${zeekLogs.slice(0, 4).map((item) => `
            <small>${item.log_type}: ${item.exists ? "ready" : "missing"}</small>
          `).join("") || `<small>No log checks available.</small>`}
        </div>
      </div>
      <small>Community packages: ${(zeek.community_packages || []).length || 0} configured through zkg.</small>
      <a class="telemetry-open-link" href="/zeek" target="_blank" rel="noopener">Open Zeek Telemetry</a>
    </div>
  `;
}

function renderMetrics(metrics) {
  const detections = metrics.detections_by_type || [];
  els.totalAlerts.textContent = metrics.total_alerts ?? 0;
  els.totalDetections.textContent = metrics.total_detections ?? 0;
  els.safeCount.textContent = metrics.outcome_counts?.safe ?? 0;
  els.reviewCount.textContent = metrics.outcome_counts?.human_review ?? 0;
  els.highRiskCount.textContent = metrics.outcome_counts?.high_risk ?? 0;
  els.dangerCount.textContent = metrics.outcome_counts?.dangerous ?? 0;
  els.totalAssets.textContent = metrics.total_assets ?? 0;
  els.zeekNoticeCount.textContent = metrics.zeek_notice_count ?? 0;
  els.zeekWeirdCount.textContent = metrics.zeek_weird_count ?? 0;
  els.investigationsReady.textContent = metrics.investigations_ready ?? 0;
  els.topDetection.textContent = detections[0] ? detectionLabel(detections[0].detection_type) : "None";
  els.systemMode.textContent = metrics.mode || "alert_only";
  els.mode.textContent = metrics.mode || "alert_only";
  document.querySelectorAll("[data-outcome-filter]").forEach((card) => {
    card.classList.toggle("selected", card.dataset.outcomeFilter === selectedOutcome);
  });
  document.querySelector("[data-outcome-all]")?.classList.toggle("selected", !selectedOutcome);

  const max = Math.max(1, ...detections.map((item) => item.count));
  const allTrafficButton = `
    <button
      class="list-item detection-button ${selectedDetectionType ? "" : "selected"}"
      type="button"
      data-detection-all="true"
      aria-pressed="${selectedDetectionType ? "false" : "true"}"
      title="Show all traffic"
    >
      <div class="row">
        <strong>All Traffic</strong>
        <span>${metrics.total_detections ?? 0}</span>
      </div>
      <div class="bar"><span style="--value:100%"></span></div>
      <small>Clear investigation filter</small>
    </button>
  `;
  els.detections.innerHTML = allTrafficButton + (detections.map((item) => `
    <a
      class="list-item detection-button ${item.detection_type === selectedDetectionType ? "selected" : ""}"
      href="${detectionWorkbookUrl(item.detection_type)}"
      target="_blank"
      rel="noopener"
      title="Open ${detectionLabel(item.detection_type)} investigation"
    >
      <div class="row">
        <strong>${detectionLabel(item.detection_type)}</strong>
        <span>${item.count}</span>
      </div>
      <div class="bar"><span style="--value:${(item.count / max) * 100}%"></span></div>
      <small>Open detection workbook</small>
    </a>
  `).join("") || `<div class="empty">No detections yet. Start ingest and generate test traffic.</div>`);
}

function renderAlerts(alerts) {
  els.alerts.innerHTML = alerts.map((alert) => {
    const findings = alert.sensor_findings || [];
    const sensors = [...new Set(findings.map((finding) => String(finding.sensor || "unknown").toLowerCase()))];
    const timestamp = alert.timestamp || findings[0]?.finding_timestamp;
    return `
      <a class="alert unified-alert investigation-link ${sensors.length > 1 ? "multi-sensor-alert" : ""}" href="${alert.detection_id ? investigationUrl(alert.detection_id, alert.case_uid) : "#"}" target="_blank" rel="noopener">
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
          <strong class="alert-signature">${escapeHtml(alert.signature || "Network detection")}</strong>
          <p class="alert-flow">
            ${escapeHtml(alert.src_ip || "unknown")}:${escapeHtml(alert.src_port || "")}
            <span aria-hidden="true">-&gt;</span>
            ${escapeHtml(alert.dest_ip || "unknown")}:${escapeHtml(alert.dest_port || "")}
            ${escapeHtml(alert.protocol || "")}
          </p>
          <div class="sensor-finding-list">
            ${findings.map((finding) => `
              <div class="sensor-finding-row">
                <span class="sensor-badge ${escapeHtml(String(finding.sensor || "unknown").toLowerCase())}">${escapeHtml(String(finding.sensor || "unknown").toUpperCase())}</span>
                <div class="sensor-finding-copy">
                  <strong>${escapeHtml(finding.event_uid || "No event UID")}</strong>
                  <span>${escapeHtml(finding.finding_name || finding.finding_type || "Finding")}</span>
                  <time>${escapeHtml(displayTimestamp(finding.finding_timestamp))}</time>
                </div>
              </div>
            `).join("") || `<small>No linked sensor findings stored.</small>`}
          </div>
        </div>
        ${scoreBadge(alert.final_score ?? 0, alert.final_classification || "Pending")}
      </a>
    `;
  }).join("") || `<div class="empty">No unified detections yet. Start Suricata and Zeek ingestion, then refresh.</div>`;
}

function classificationClass(value) {
  const normalized = String(value || "").toLowerCase();
  if (normalized.includes("dangerous")) return "danger";
  if (normalized.includes("human")) return "review";
  return "safe";
}

function renderAiModelReports(reports) {
  els.aiReports.innerHTML = reports.map((report) => `
    <a class="alert ai-opinion investigation-link ${classificationClass(report.classification)}" href="${report.detection_id ? investigationUrl(report.detection_id, report.case_uid) : "#"}" target="_blank" rel="noopener">
      <time>${report.created_at || report.timestamp || ""}</time>
      <div>
        <div class="row tight">
          <strong>${report.classification || "AI opinion"}</strong>
          <span>${report.confidence || "Unknown"} confidence · ${report.model_identity || "unknown model"}</span>
        </div>
        <p>
          ${report.src_ip || "unknown"} -> ${report.dest_ip || "unknown"}
          ${report.signature || ""}
        </p>
        <p>${detectionLabel(report.sensor_state || "suricata_only")} · ${detectionLabel(report.agreement_state || "single_sensor")}</p>
        <p>${report.reason || "No reason returned."}</p>
        <p>Recommended action: ${report.recommended_action || "none"} · risk adjustment ${report.risk_adjustment ?? 0}</p>
        <p>Profile ${report.ai_profile_uid || "legacy-profile"} · run ${report.model_run_id || "not recorded"} · ${report.elapsed_ms ?? 0}ms</p>
      </div>
    </a>
  `).join("") || `<div class="empty">No AI opinions yet. Start ingest and confirm the AI model is reachable.</div>`;
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

function renderDecisionEvidence(rows) {
  const outcomeLabel = selectedOutcome ? detectionLabel(selectedOutcome) : "All Outcomes";
  els.decisionEvidence.innerHTML = rows.map((row) => `
    <article class="evidence-item">
      <div class="row tight">
        <strong>${row.final_classification || "Decision"}</strong>
        <time class="evidence-timestamp">${escapeHtml(displayTimestamp(row.timestamp || row.first_seen))}</time>
      </div>
      ${scoreBadge(row.final_score ?? 0, "Final")}
      <div class="evidence-chain">
        <div>
          <span>Sensor Finding</span>
          <strong>${row.signature || "Network detection"}</strong>
          <small>${detectionLabel(row.sensor_state || "single_sensor")} · ${row.src_ip || "unknown"}:${row.src_port || ""} -> ${row.dest_ip || "unknown"}:${row.dest_port || ""}</small>
          <small>${(row.sensor_findings || []).map((finding) => `${String(finding.sensor || "unknown").toUpperCase()}: ${finding.finding_name || finding.finding_type || "finding"}`).join(" · ") || `priority ${row.priority || "unknown"}`}</small>
        </div>
        <div>
          <span>Correlation</span>
          <strong>${detectionLabel(row.detection_type)}</strong>
          <small>${detectionLabel(row.sensor_state || "suricata_only")} · ${detectionLabel(row.agreement_state || "single_sensor")} · ${row.alert_count || 0} events · ${row.unique_dest_ports || 0} ports · ${row.mitre_id || "no MITRE"}</small>
        </div>
        <div>
          <span>Scoring</span>
          <strong>Python ${row.python_initial_score ?? 0} + AI ${row.ai_risk_adjustment ?? 0}</strong>
          <small>
            Final score ${row.final_score ?? 0}
            ${row.src_asset || row.dest_asset ? ` · asset ${row.src_asset?.name || row.dest_asset?.name} score ${row.src_asset?.asset_score ?? row.dest_asset?.asset_score}` : " · no asset score yet"}
          </small>
        </div>
        <div>
          <span>AI Model</span>
          <strong>${row.ai_classification || "No opinion"} ${row.ai_confidence ? `(${row.ai_confidence})` : ""}</strong>
          <small>${row.ai_model_identity || "unknown model"} · profile ${row.ai_profile_uid || "legacy-profile"} · run ${row.ai_model_run_id || "not recorded"}</small>
          <small>${row.ai_reason || "No AI reason stored."}</small>
        </div>
        <div>
          <span>Analyst</span>
          <strong>${row.review_status || "No review"}</strong>
          <small>${row.analyst_action || "No analyst override"} ${row.analyst_name ? `by ${row.analyst_name}` : ""}</small>
        </div>
      </div>
      <a class="text-button evidence-open" href="${investigationUrl(row.detection_id, row.case_uid)}" target="_blank" rel="noopener">Open Investigation</a>
    </article>
  `).join("") || `<div class="empty">No ${outcomeLabel} decision evidence rows for this selection yet.</div>`;
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

function renderAssetTypeOptions(types) {
  const currentValue = els.assetType.value;
  els.assetType.innerHTML = (types || []).map((type) => `
    <option value="${type.value}" data-score="${type.default_score}">
      ${type.label} (${type.default_score})
    </option>
  `).join("");
  if (currentValue) els.assetType.value = currentValue;
  if (!els.assetScore.value) {
    const selected = els.assetType.selectedOptions[0];
    els.assetScore.value = selected ? selected.dataset.score : "";
  }
}

function renderAssets(payload) {
  renderAssetTypeOptions(payload.types || []);
  if (!els.assetInterface.value) {
    els.assetInterface.placeholder = payload.default_interface || "ens37";
  }

  const summary = payload.summary || {};
  const assets = payload.assets || [];
  els.assets.innerHTML = `
    <div class="list-item">
      <div class="row tight">
        <strong>Tracked inventory records</strong>
        <span>${summary.total || 0}</span>
      </div>
      <p>Manual inventory for the internal interface, used as decision context.</p>
    </div>
    ${assets.map((asset) => `
      <div class="list-item asset-item">
        <div class="row tight">
          <strong>${asset.name}</strong>
          <span>score ${asset.asset_score}</span>
        </div>
        <p>${asset.ip_address} · ${detectionLabel(asset.device_type)} · ${asset.network_interface || "ens37"}</p>
        <small>${asset.function || "No function"}${asset.notes ? ` · ${asset.notes}` : ""}</small>
        <button class="text-button" type="button" data-asset-remove="${asset.id}">Deactivate</button>
      </div>
    `).join("")}
  `;
}

async function refresh(options = {}) {
  const preserveScroll = Boolean(options.preserveScroll);
  const scrollX = window.scrollX;
  const scrollY = window.scrollY;
  try {
    els.refresh.disabled = true;
    els.refresh.textContent = "Refreshing";
    const evidencePath = selectedDetectionType
      ? `/api/decision-evidence?detection_type=${encodeURIComponent(selectedDetectionType)}&limit=20${selectedOutcome ? `&outcome=${encodeURIComponent(selectedOutcome)}` : ""}`
      : `/api/decision-evidence?limit=20${selectedOutcome ? `&outcome=${encodeURIComponent(selectedOutcome)}` : ""}`;
    const summaryRequest = getJson("/api/dashboard-summary?limit=12").catch((error) => ({ _error: error.message }));
    const [metrics, summary, alerts, aiReports, allowlist, assets, events, evidence] = await Promise.all([
      getJson("/api/metrics"),
      summaryRequest,
      getJson(`/api/latest-alerts?limit=50&sensor=${encodeURIComponent(selectedSensorFilter)}`),
      getJson("/api/ai-opinions?limit=50"),
      getJson("/api/allowlist?limit=25"),
      getJson("/api/assets?limit=25"),
      getJson("/api/events?limit=40"),
      getJson(evidencePath)
    ]);
    renderMetrics(metrics);
    renderSummary(summary);
    renderAlerts(alerts);
    renderAiModelReports(aiReports);
    renderAllowlist(allowlist);
    renderAssets(assets);
    renderEvents(events);
    renderDecisionEvidence(evidence);
    els.updated.textContent = `Updated ${new Date().toLocaleTimeString()}`;
  } catch (error) {
    els.updated.textContent = "Dashboard API error";
    els.alerts.innerHTML = `<div class="empty">${error.message}</div>`;
    els.aiReports.innerHTML = `<div class="empty">${error.message}</div>`;
    els.allowlist.innerHTML = `<div class="empty">${error.message}</div>`;
    els.assets.innerHTML = `<div class="empty">${error.message}</div>`;
    els.events.innerHTML = `<div class="empty">${error.message}</div>`;
    els.decisionEvidence.innerHTML = `<div class="empty">${error.message}</div>`;
    els.summaryIpPie.innerHTML = `<div class="empty">${error.message}</div>`;
    els.summaryTimeline.innerHTML = `<div class="empty">${error.message}</div>`;
    els.summaryModels.innerHTML = `<div class="empty">${error.message}</div>`;
    els.summaryEncrypted.innerHTML = `<div class="empty">${error.message}</div>`;
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
  const confirmText = window.prompt("Type RESET to clear dashboard logs, alerts, detections, AI reports, reviews, evidence, and cached threat intel. Asset inventory and allowlist entries are kept.");
  if (confirmText !== "RESET") return;
  await sendJson("/api/reset-logs", "POST", { confirm: confirmText });
  selectedDetectionType = null;
  selectedOutcome = null;
  writeHashFilters();
  refresh();
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

async function addAsset(event) {
  event.preventDefault();
  const form = new FormData(els.assetForm);
  const score = form.get("asset_score");
  await sendJson("/api/assets", "POST", {
    ip_address: form.get("ip_address"),
    name: form.get("name"),
    device_type: form.get("device_type"),
    network_interface: form.get("network_interface"),
    asset_score: score === "" ? null : Number(score),
    function: form.get("function"),
    notes: form.get("notes")
  });
  els.assetForm.reset();
  const selected = els.assetType.selectedOptions[0];
  els.assetScore.value = selected ? selected.dataset.score : "";
  refresh();
}

async function handleDashboardClick(event) {
  const sensorFilterButton = event.target.closest ? event.target.closest("[data-sensor-filter]") : null;
  if (sensorFilterButton) {
    selectedSensorFilter = sensorFilterButton.dataset.sensorFilter || "all";
    document.querySelectorAll("[data-sensor-filter]").forEach((button) => {
      button.classList.toggle("selected", button === sensorFilterButton);
    });
    refresh({ preserveScroll: true });
    return;
  }

  const outcomeAll = event.target.closest ? event.target.closest("[data-outcome-all]") : null;
  if (outcomeAll) {
    window.open(outcomeWorkbookUrl("all"), "_blank", "noopener");
    return;
  }

  const outcomeCard = event.target.closest ? event.target.closest("[data-outcome-filter]") : null;
  const outcome = outcomeCard ? outcomeCard.dataset.outcomeFilter : null;
  if (outcome) {
    window.open(outcomeWorkbookUrl(outcome), "_blank", "noopener");
    return;
  }

  const allTrafficButton = event.target.closest ? event.target.closest("[data-detection-all]") : null;
  if (allTrafficButton) {
    selectedDetectionType = null;
    writeHashFilters();
    refresh();
    return;
  }

  const detectionButton = event.target.closest ? event.target.closest("[data-detection-type]") : null;
  const detectionType = detectionButton ? detectionButton.dataset.detectionType : null;
  if (detectionType) {
    window.open(detectionWorkbookUrl(detectionType), "_blank", "noopener");
    return;
  }

  const assetInventoryButton = event.target.closest ? event.target.closest("[data-asset-inventory]") : null;
  if (assetInventoryButton) {
    window.open(assetInventoryUrl(), "_blank", "noopener");
    return;
  }

  const removeId = event.target.dataset.allowRemove;
  if (removeId) {
    await sendJson(`/api/allowlist/${removeId}`, "DELETE");
    refresh();
    return;
  }

  const assetRemoveId = event.target.dataset.assetRemove;
  if (assetRemoveId) {
    await sendJson(`/api/assets/${assetRemoveId}`, "DELETE");
    refresh();
    return;
  }

}

els.refresh.addEventListener("click", refresh);
els.checkAiModel.addEventListener("click", checkAiModel);
els.resetLogs.addEventListener("click", resetLogs);
els.allowlistForm.addEventListener("submit", addAllowlistEntry);
els.assetForm.addEventListener("submit", addAsset);
els.assetType.addEventListener("change", () => {
  const selected = els.assetType.selectedOptions[0];
  els.assetScore.value = selected ? selected.dataset.score : "";
});
document.addEventListener("click", handleDashboardClick);
refresh();

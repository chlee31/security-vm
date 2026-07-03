const els = {
  totalAlerts: document.querySelector("#total-alerts"),
  totalDetections: document.querySelector("#total-detections"),
  safeCount: document.querySelector("#safe-count"),
  reviewCount: document.querySelector("#review-count"),
  dangerCount: document.querySelector("#danger-count"),
  totalAssets: document.querySelector("#total-assets"),
  topDetection: document.querySelector("#top-detection"),
  systemMode: document.querySelector("#system-mode"),
  summaryIpPie: document.querySelector("#summary-ip-pie"),
  summaryTimeline: document.querySelector("#summary-timeline"),
  summaryOtx: document.querySelector("#summary-otx"),
  summaryModels: document.querySelector("#summary-models"),
  decisionEvidence: document.querySelector("#decision-evidence"),
  pcapFiles: document.querySelector("#pcap-files"),
  mode: document.querySelector("#mode"),
  updated: document.querySelector("#updated"),
  alerts: document.querySelector("#alerts"),
  ollamaReports: document.querySelector("#ollama-reports"),
  detections: document.querySelector("#detections"),
  allowlist: document.querySelector("#allowlist"),
  allowlistForm: document.querySelector("#allowlist-form"),
  assets: document.querySelector("#assets"),
  assetForm: document.querySelector("#asset-form"),
  assetType: document.querySelector("#asset-type"),
  assetInterface: document.querySelector("#asset-interface"),
  assetScore: document.querySelector("#asset-score"),
  enrichment: document.querySelector("#enrichment"),
  threatIntelForm: document.querySelector("#threat-intel-form"),
  otxEnabled: document.querySelector("#otx-enabled"),
  otxCacheTtl: document.querySelector("#otx-cache-ttl"),
  otxApiKey: document.querySelector("#otx-api-key"),
  otxLookupScope: document.querySelector("#otx-lookup-scope"),
  otxStatus: document.querySelector("#otx-status"),
  testOtx: document.querySelector("#test-otx"),
  runOtx: document.querySelector("#run-otx"),
  events: document.querySelector("#events"),
  checkOllama: document.querySelector("#check-ollama"),
  resetLogs: document.querySelector("#reset-logs"),
  refresh: document.querySelector("#refresh")
};

let selectedDetectionType = null;
let selectedOutcome = null;
let selectedOtxReputation = null;

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

function investigationUrl(detectionId) {
  return `/investigation?id=${encodeURIComponent(detectionId)}`;
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
            <strong>${labelFn(item)}</strong>
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
    els.summaryOtx.innerHTML = `<div class="empty">${message}</div>`;
    els.summaryModels.innerHTML = `<div class="empty">${message}</div>`;
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

  const otxSource = (summary.otx?.sources || []).find((source) => source.name === "otx") || {};
  const reputationRows = summary.otx?.by_reputation || [];
  const lookupsByReputation = summary.otx?.lookups_by_reputation || {};
  if (selectedOtxReputation && !lookupsByReputation[selectedOtxReputation]) {
    selectedOtxReputation = null;
  }
  const selectedOtxRows = selectedOtxReputation ? lookupsByReputation[selectedOtxReputation] || [] : [];
  els.summaryOtx.innerHTML = `
    <div class="summary-stack">
      <div class="summary-cardline">
        <strong>${otxSource.status || "unknown"}</strong>
        <span>${summary.otx?.lookup_count || 0} lookups</span>
      </div>
      <small>${otxSource.api_key_configured ? "API key configured" : "API key not configured"} · ${otxSource.cache_ttl_hours || 24}h cache</small>
      <div class="bar-list compact-bars">
        ${reputationRows.map((row) => `
          <button class="summary-drill-row ${selectedOtxReputation === (row.reputation || "unknown") ? "selected" : ""}" type="button" data-otx-reputation="${row.reputation || "unknown"}">
            <div class="row tight">
              <strong>${row.reputation || "unknown"}</strong>
              <span>${row.count}</span>
            </div>
            <small>malicious ${row.malicious_total || 0} · suspicious ${row.suspicious_total || 0}</small>
          </button>
        `).join("") || `<div class="empty">No cached OTX results yet.</div>`}
      </div>
      ${selectedOtxReputation ? `
        <div class="otx-drilldown">
          <div class="summary-cardline">
            <strong>${selectedOtxReputation} IPs</strong>
            <span>${selectedOtxRows.length}</span>
          </div>
          <div class="mini-list dense">
            ${selectedOtxRows.slice(0, 10).map((item) => `
              <div>
                <strong>${item.indicator}</strong>
                <small>malicious ${item.malicious_count || 0} · suspicious ${item.suspicious_count || 0}</small>
                <small>${item.lookup_result || "No OTX detail"}${item.lookup_time ? ` · ${item.lookup_time}` : ""}</small>
              </div>
            `).join("") || `<small>No IPs found for this reputation.</small>`}
          </div>
        </div>
      ` : `<small>Click a reputation row to see searched IP addresses.</small>`}
    </div>
  `;

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
}

function renderMetrics(metrics) {
  const detections = metrics.detections_by_type || [];
  els.totalAlerts.textContent = metrics.total_alerts ?? 0;
  els.totalDetections.textContent = metrics.total_detections ?? 0;
  els.safeCount.textContent = metrics.outcome_counts?.safe ?? 0;
  els.reviewCount.textContent = metrics.outcome_counts?.human_review ?? 0;
  els.dangerCount.textContent = metrics.outcome_counts?.dangerous ?? 0;
  els.totalAssets.textContent = metrics.total_assets ?? 0;
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
  els.alerts.innerHTML = alerts.map((alert) => `
    <a class="alert investigation-link" href="${alert.detection_id ? investigationUrl(alert.detection_id) : "#"}" target="_blank" rel="noopener">
      <time>${alert.timestamp || ""}</time>
      <div>
        <strong>${alert.signature || "Suricata alert"}</strong>
        <p>
          ${alert.src_ip || "unknown"}:${alert.src_port || ""} ->
          ${alert.dest_ip || "unknown"}:${alert.dest_port || ""}
          ${alert.protocol || ""}
        </p>
        <p>${alert.category || "unknown"} · priority ${alert.priority || "unknown"}</p>
        ${alert.final_classification ? `<p>${alert.final_classification} · score ${alert.final_score ?? 0}</p>` : ""}
      </div>
      <div class="score-badge priority">
        <span>Priority</span>
        <strong>${alert.priority || "?"}</strong>
      </div>
    </a>
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
    <a class="alert ollama investigation-link ${classificationClass(report.classification)}" href="${report.detection_id ? investigationUrl(report.detection_id) : "#"}" target="_blank" rel="noopener">
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

function renderOtxSummary(result) {
  if (!result) return "OTX no lookup yet";
  const reputation = result.reputation || "unknown";
  const malicious = result.malicious_count ?? 0;
  const suspicious = result.suspicious_count ?? 0;
  const cached = result.cached ? "cached" : "fresh";
  return `OTX ${reputation} · malicious ${malicious} · suspicious ${suspicious} · ${cached}`;
}

function renderEnrichment(status) {
  const sources = status.sources || [];
  const topIps = status.top_ips || [];
  const otx = sources.find((source) => source.name === "otx") || {};
  els.otxEnabled.checked = Boolean(otx.enabled);
  els.otxCacheTtl.value = status.cache_policy?.ttl_hours || 24;
  els.otxApiKey.placeholder = otx.api_key_configured ? "OTX API key saved" : "OTX API key";
  if (!otx.api_key_configured && !els.otxApiKey.value) {
    els.otxStatus.className = "connection-status warn";
    els.otxStatus.textContent = "OTX key not configured.";
  } else if (!els.otxStatus.dataset.manual) {
    els.otxStatus.className = "connection-status";
    els.otxStatus.textContent = "OTX connection not tested.";
  }
  els.enrichment.innerHTML = `
    <div class="list-item">
      <div class="row tight">
        <strong>Cache policy</strong>
        <span>${status.cache_policy?.ttl_hours || 24}h TTL</span>
      </div>
      <p>${status.cache_policy?.notes || "Recent lookups are reused from SQLite."}</p>
    </div>
    ${sources.map((source) => `
      <div class="list-item enrichment-source ${source.status}">
        <div class="row tight">
          <strong>${source.name}</strong>
          <span>${source.status}${source.cache_ttl_hours ? ` · ${source.cache_ttl_hours}h cache` : ""}</span>
        </div>
        <p>${source.notes}</p>
        ${source.api_key_configured !== undefined ? `<small>API key configured: ${source.api_key_configured ? "yes" : "no"}</small>` : ""}
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
  const outcomeLabel = selectedOutcome ? detectionLabel(selectedOutcome) : "All Outcomes";
  els.decisionEvidence.innerHTML = rows.map((row) => `
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
          <small>${row.src_ip || "unknown"}:${row.src_port || ""} -> ${row.dest_ip || "unknown"}:${row.dest_port || ""} · priority ${row.priority || "unknown"}</small>
        </div>
        <div>
          <span>Correlation</span>
          <strong>${detectionLabel(row.detection_type)}</strong>
          <small>${row.alert_count || 0} alerts · ${row.unique_dest_ports || 0} ports · ${row.mitre_id || "no MITRE"}</small>
        </div>
        <div>
          <span>Scoring</span>
          <strong>Python ${row.python_initial_score ?? 0} + AI ${row.ollama_risk_adjustment ?? 0}</strong>
          <small>
            Final score ${row.final_score ?? 0}
            ${row.src_asset || row.dest_asset ? ` · asset ${row.src_asset?.name || row.dest_asset?.name} score ${row.src_asset?.asset_score ?? row.dest_asset?.asset_score}` : " · no asset score yet"}
          </small>
        </div>
        <div>
          <span>AI Model</span>
          <strong>${row.ollama_classification || "No opinion"} ${row.ollama_confidence ? `(${row.ollama_confidence})` : ""}</strong>
          <small>${row.ollama_model_identity || "unknown model"} · profile ${row.ollama_ai_profile_uid || "legacy-profile"} · run ${row.ollama_model_run_id || "not recorded"}</small>
          <small>${row.ollama_reason || "No AI reason stored."}</small>
        </div>
        <div>
          <span>Analyst</span>
          <strong>${row.review_status || "No review"}</strong>
          <small>${row.analyst_action || "No analyst override"} ${row.analyst_name ? `by ${row.analyst_name}` : ""}</small>
        </div>
      </div>
      <a class="text-button evidence-open" href="${investigationUrl(row.detection_id)}" target="_blank" rel="noopener">Open Investigation</a>
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
        <strong>Tracked assets</strong>
        <span>${summary.total || 0}</span>
      </div>
      <p>Manual inventory for the internal interface, currently used as WIP decision context.</p>
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

async function refresh() {
  try {
    const pcapPath = selectedDetectionType
      ? `/api/pcap-files?detection_type=${encodeURIComponent(selectedDetectionType)}`
      : "/api/pcap-files";
    const evidencePath = selectedDetectionType
      ? `/api/decision-evidence?detection_type=${encodeURIComponent(selectedDetectionType)}&limit=20${selectedOutcome ? `&outcome=${encodeURIComponent(selectedOutcome)}` : ""}`
      : `/api/decision-evidence?limit=20${selectedOutcome ? `&outcome=${encodeURIComponent(selectedOutcome)}` : ""}`;
    const summaryRequest = getJson("/api/dashboard-summary?limit=12").catch((error) => ({ _error: error.message }));
    const [metrics, summary, alerts, ollamaReports, allowlist, assets, enrichment, events, pcaps, evidence] = await Promise.all([
      getJson("/api/metrics"),
      summaryRequest,
      getJson("/api/alerts?limit=50"),
      getJson("/api/ollama-reports?limit=50"),
      getJson("/api/allowlist?limit=25"),
      getJson("/api/assets?limit=25"),
      getJson("/api/enrichment-status?limit=25"),
      getJson("/api/events?limit=40"),
      getJson(pcapPath),
      getJson(evidencePath)
    ]);
    renderMetrics(metrics);
    renderSummary(summary);
    renderAlerts(alerts);
    renderOllamaReports(ollamaReports);
    renderAllowlist(allowlist);
    renderAssets(assets);
    renderEnrichment(enrichment);
    renderEvents(events);
    renderPcapFiles(pcaps);
    renderDecisionEvidence(evidence);
    els.updated.textContent = new Date().toLocaleTimeString();
  } catch (error) {
    els.updated.textContent = "Dashboard API error";
    els.alerts.innerHTML = `<div class="empty">${error.message}</div>`;
    els.ollamaReports.innerHTML = `<div class="empty">${error.message}</div>`;
    els.allowlist.innerHTML = `<div class="empty">${error.message}</div>`;
    els.assets.innerHTML = `<div class="empty">${error.message}</div>`;
    els.enrichment.innerHTML = `<div class="empty">${error.message}</div>`;
    els.events.innerHTML = `<div class="empty">${error.message}</div>`;
    els.pcapFiles.innerHTML = `<div class="empty">${error.message}</div>`;
    els.decisionEvidence.innerHTML = `<div class="empty">${error.message}</div>`;
    els.summaryIpPie.innerHTML = `<div class="empty">${error.message}</div>`;
    els.summaryTimeline.innerHTML = `<div class="empty">${error.message}</div>`;
    els.summaryOtx.innerHTML = `<div class="empty">${error.message}</div>`;
    els.summaryModels.innerHTML = `<div class="empty">${error.message}</div>`;
  }
}

async function checkOllama() {
  els.updated.textContent = "Checking AI model";
  try {
    await getJson("/api/ollama-status");
  } finally {
    refresh();
  }
}

async function resetLogs() {
  const confirmText = window.prompt("Type RESET to clear dashboard logs, alerts, detections, AI reports, reviews, evidence, and cached threat intel. Assets and allowlist entries are kept.");
  if (confirmText !== "RESET") return;
  await sendJson("/api/reset-logs", "POST", { confirm: confirmText });
  selectedDetectionType = null;
  selectedOutcome = null;
  writeHashFilters();
  refresh();
}

async function saveThreatIntelSettingsFromForm(forceEnable = false) {
  const form = new FormData(els.threatIntelForm);
  return sendJson("/api/threat-intel-config", "POST", {
    otx_enabled: forceEnable || form.get("otx_enabled") === "on",
    otx_api_key: form.get("otx_api_key") || "",
    cache_ttl_hours: Number(form.get("cache_ttl_hours") || 24)
  });
}

async function saveThreatIntelSettings(event) {
  event.preventDefault();
  await saveThreatIntelSettingsFromForm();
  els.otxApiKey.value = "";
  refresh();
}

async function testOtxConnection() {
  els.otxStatus.dataset.manual = "true";
  els.otxStatus.className = "connection-status warn";
  els.otxStatus.textContent = "Testing OTX connection...";
  const result = await sendJson("/api/otx-status", "POST", {
    otx_api_key: els.otxApiKey.value || ""
  });
  if (result.ok) {
    els.otxStatus.className = "connection-status ok";
    els.otxStatus.textContent = `OTX connected. Subscribed pulses: ${result.pulse_count ?? 0}.`;
  } else {
    els.otxStatus.className = "connection-status error";
    els.otxStatus.textContent = `OTX failed: ${result.error || result.status || "unknown error"}`;
  }
  refresh();
}

async function runOtxLookups() {
  const scope = els.otxLookupScope.value || "top5";
  const limitByScope = { top5: 5, top10: 10, visible: 50 };
  els.otxStatus.dataset.manual = "true";
  els.otxStatus.className = "connection-status warn";
  els.otxStatus.textContent = "Running OTX lookups...";
  els.updated.textContent = "Running OTX lookups";
  try {
    await saveThreatIntelSettingsFromForm(true);
    els.otxEnabled.checked = true;
    const lookupPayload = {
      scope,
      limit: limitByScope[scope] || 5
    };
    if (scope === "visible" && selectedDetectionType) {
      lookupPayload.detection_type = selectedDetectionType;
    }
    const result = await sendJson("/api/otx-lookups", "POST", lookupPayload);
    const okCount = (result.results || []).filter((item) => item.status === "ok").length;
    const errors = (result.results || []).filter((item) => item.status === "error");
    const errorCount = errors.length;
    const totalCount = (result.results || []).length;
    els.otxStatus.className = errorCount ? "connection-status warn" : "connection-status ok";
    const firstError = errors[0] ? ` First error ${errors[0].ip_address}: ${errors[0].error}` : "";
    els.otxStatus.textContent = result.message || `OTX lookups complete. Checked ${totalCount}; saved ${okCount}; errors ${errorCount}.${firstError}`;
    refresh();
  } catch (error) {
    els.otxStatus.className = "connection-status error";
    els.otxStatus.textContent = `OTX lookup failed: ${error.message}`;
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

  const otxReputationButton = event.target.closest ? event.target.closest("[data-otx-reputation]") : null;
  if (otxReputationButton) {
    const reputation = otxReputationButton.dataset.otxReputation;
    selectedOtxReputation = selectedOtxReputation === reputation ? null : reputation;
    refresh();
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
els.checkOllama.addEventListener("click", checkOllama);
els.resetLogs.addEventListener("click", resetLogs);
els.threatIntelForm.addEventListener("submit", saveThreatIntelSettings);
els.testOtx.addEventListener("click", testOtxConnection);
els.runOtx.addEventListener("click", runOtxLookups);
els.allowlistForm.addEventListener("submit", addAllowlistEntry);
els.assetForm.addEventListener("submit", addAsset);
els.assetType.addEventListener("change", () => {
  const selected = els.assetType.selectedOptions[0];
  els.assetScore.value = selected ? selected.dataset.score : "";
});
document.addEventListener("click", handleDashboardClick);
refresh();
setInterval(refresh, 2000);

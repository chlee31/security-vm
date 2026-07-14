const els = {
  dot: document.querySelector("#zeek-dot"),
  updated: document.querySelector("#zeek-updated"),
  refresh: document.querySelector("#zeek-refresh"),
  state: document.querySelector("#zeek-state"),
  interface: document.querySelector("#zeek-interface"),
  total: document.querySelector("#zeek-total"),
  logTypes: document.querySelector("#zeek-log-types"),
  latest: document.querySelector("#zeek-latest"),
  checkpoints: document.querySelector("#zeek-checkpoints"),
  counts: document.querySelector("#zeek-counts"),
  activity: document.querySelector("#zeek-activity"),
  tlsSummary: document.querySelector("#zeek-tls-summary"),
  tlsValidation: document.querySelector("#zeek-tls-validation"),
  tlsRecent: document.querySelector("#zeek-tls-recent"),
  fileSummary: document.querySelector("#zeek-file-summary"),
  fileSources: document.querySelector("#zeek-file-sources"),
  fileRecent: document.querySelector("#zeek-file-recent"),
  dnsQueries: document.querySelector("#zeek-dns-queries"),
  dnsTypes: document.querySelector("#zeek-dns-types"),
  httpHosts: document.querySelector("#zeek-http-hosts"),
  httpMethods: document.querySelector("#zeek-http-methods"),
  events: document.querySelector("#zeek-events"),
  eventFilter: document.querySelector("#zeek-event-filter")
};

let telemetry = null;

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

async function getJson(path) {
  const response = await fetch(path, { cache: "no-store" });
  if (!response.ok) throw new Error(`${path} returned ${response.status}`);
  return response.json();
}

function formatNumber(value) {
  return new Intl.NumberFormat().format(Number(value || 0));
}

function formatBytes(value) {
  const bytes = Number(value || 0);
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let amount = bytes / 1024;
  let index = 0;
  while (amount >= 1024 && index < units.length - 1) {
    amount /= 1024;
    index += 1;
  }
  return `${amount.toFixed(amount >= 10 ? 1 : 2)} ${units[index]}`;
}

function formatTime(value) {
  if (!value) return "not recorded";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function investigationUrl(item) {
  if (item.case_uid) return `/investigation?case=${encodeURIComponent(item.case_uid)}`;
  if (item.detection_id) return `/investigation?id=${encodeURIComponent(item.detection_id)}`;
  return "";
}

function bars(rows, labelKey, emptyText = "No observations yet.") {
  if (!rows?.length) return `<div class="empty">${escapeHtml(emptyText)}</div>`;
  const max = Math.max(1, ...rows.map((row) => Number(row.count || 0)));
  return `<div class="bar-list compact-bars">${rows.map((row) => `
    <div>
      <div class="row tight"><strong>${escapeHtml(row[labelKey] || "unknown")}</strong><span>${formatNumber(row.count)}</span></div>
      <div class="bar"><span style="--value:${(Number(row.count || 0) / max) * 100}%"></span></div>
    </div>
  `).join("")}</div>`;
}

function renderOverview(data) {
  const runtime = data.runtime || {};
  els.state.textContent = runtime.running ? "Running" : runtime.installed ? "Stopped" : "Missing";
  els.interface.textContent = `${runtime.interface || "No interface"} · ${runtime.log_directory || "No log directory"}`;
  els.total.textContent = formatNumber(data.total_events);
  els.logTypes.textContent = formatNumber(data.active_log_types);
  els.latest.textContent = formatTime(data.last_event);
  els.dot.classList.toggle("offline", !runtime.running);

  els.checkpoints.innerHTML = (data.checkpoints || []).map((item) => `
    <article class="telemetry-row">
      <div><strong>${escapeHtml(item.log_type)}</strong><small>${escapeHtml(item.path)}</small></div>
      <div class="telemetry-facts"><span>${formatBytes(item.offset)} read</span><time>${escapeHtml(formatTime(item.updated_at))}</time></div>
    </article>
  `).join("") || `<div class="empty">No ingest checkpoints stored. Start zeek-ingest.</div>`;

  const countRows = Object.entries(data.event_counts || {})
    .map(([log_type, count]) => ({ log_type, count }))
    .sort((a, b) => b.count - a.count);
  els.counts.innerHTML = bars(countRows, "log_type", "No Zeek events are stored yet.");
  els.activity.innerHTML = bars(data.activity || [], "hour", "No Zeek activity is stored yet.");

  const options = [`<option value="">All logs</option>`].concat(
    countRows.map((item) => `<option value="${escapeHtml(item.log_type)}">${escapeHtml(item.log_type)} (${formatNumber(item.count)})</option>`)
  );
  const selected = els.eventFilter.value;
  els.eventFilter.innerHTML = options.join("");
  els.eventFilter.value = selected;
}

function renderTls(data) {
  const tls = data.tls || {};
  els.tlsSummary.innerHTML = `
    <div class="telemetry-callout"><strong>${formatNumber(tls.count)}</strong><span>TLS session records</span></div>
    <h3>Versions</h3>${bars(tls.versions, "version")}
    <h3>Top server names</h3>${bars(tls.top_server_names, "server_name")}
  `;
  els.tlsValidation.innerHTML = bars(tls.validation, "status", "No certificate validation results yet.");
  els.tlsRecent.innerHTML = (tls.recent || []).map((item) => `
    <article class="telemetry-row telemetry-detail-row">
      <div>
        <strong>${escapeHtml(item.server_name || item.destination_ip || "TLS session")}</strong>
        <small>${escapeHtml(item.source_ip || "unknown")} : ${escapeHtml(item.source_port || "-")} → ${escapeHtml(item.destination_ip || "unknown")} : ${escapeHtml(item.destination_port || "-")}</small>
        <small>${escapeHtml(item.version || "unknown version")} · ${escapeHtml(item.cipher || "cipher not recorded")}</small>
      </div>
      <div class="telemetry-facts"><span class="${item.sni_matches_cert === false ? "fact-warning" : ""}">${escapeHtml(item.validation_status || "validation not recorded")}</span><time>${escapeHtml(formatTime(item.timestamp))}</time></div>
    </article>
  `).join("") || `<div class="empty">No TLS metadata yet.</div>`;
}

function renderFiles(data) {
  const files = data.files || {};
  els.fileSummary.innerHTML = `
    <div class="telemetry-callout"><strong>${formatNumber(files.count)}</strong><span>file metadata records</span></div>
    <div class="telemetry-callout"><strong>${formatBytes(files.observed_bytes_recent)}</strong><span>observed across the latest 1,000 records</span></div>
    ${bars(files.mime_types, "mime_type")}
  `;
  els.fileSources.innerHTML = bars(files.sources, "source", "No file source protocols recorded.");
  els.fileRecent.innerHTML = (files.recent || []).map((item) => `
    <article class="telemetry-row telemetry-detail-row">
      <div>
        <strong>${escapeHtml(item.filename || item.mime_type || "Unknown file type")}</strong>
        <small>${escapeHtml(item.source || "unknown source")} · ${escapeHtml(item.source_ip || "unknown")} → ${escapeHtml(item.destination_ip || "unknown")}</small>
        <small>FUID ${escapeHtml(item.fuid || "not recorded")} · MD5 ${escapeHtml(item.md5 || "not calculated")} · SHA1 ${escapeHtml(item.sha1 || "not calculated")}</small>
      </div>
      <div class="telemetry-facts"><span>${formatBytes(item.seen_bytes)} observed · ${formatBytes(item.missing_bytes)} missing</span><time>${escapeHtml(formatTime(item.timestamp))}</time></div>
    </article>
  `).join("") || `<div class="empty">No file observations yet.</div>`;
}

function renderDnsHttp(data) {
  const dns = data.dns || {};
  const http = data.http || {};
  els.dnsQueries.innerHTML = bars(dns.top_queries, "query", "No DNS queries stored.");
  els.dnsTypes.innerHTML = `<h3>Query types</h3>${bars(dns.query_types, "query_type")}<h3>Response codes</h3>${bars(dns.response_codes, "response_code")}`;
  els.httpHosts.innerHTML = bars(http.top_hosts, "host", "No HTTP hosts stored.");
  els.httpMethods.innerHTML = `<h3>Methods</h3>${bars(http.methods, "method")}<h3>Status codes</h3>${bars(http.statuses, "status")}`;
}

function renderEventRows(rows) {
  els.events.innerHTML = rows.map((item) => {
    const href = investigationUrl(item);
    return `
      <article class="telemetry-row telemetry-event-row">
        <div>
          <div class="sensor-badges"><span class="sensor-badge zeek">${escapeHtml(item.log_type)}</span><span>${escapeHtml(item.event_uid || `Zeek #${item.id}`)}</span></div>
          <strong>${escapeHtml(item.event_name || item.message || "Zeek event")}</strong>
          <small>${escapeHtml(item.source_ip || "unknown")} : ${escapeHtml(item.source_port || "-")} → ${escapeHtml(item.destination_ip || "unknown")} : ${escapeHtml(item.destination_port || "-")} ${escapeHtml(item.protocol || "")}</small>
          <small>${escapeHtml(item.message || "")}${item.sub_message ? ` · ${escapeHtml(item.sub_message)}` : ""}</small>
          ${href ? `<a class="inline-link" href="${href}" target="_blank" rel="noopener">Open correlated investigation</a>` : ""}
          <details class="command-details"><summary>Metadata</summary><pre class="raw-json">${escapeHtml(item.raw_json || "{}")}</pre></details>
        </div>
        <div class="telemetry-facts"><time>${escapeHtml(formatTime(item.timestamp))}</time></div>
      </article>
    `;
  }).join("") || `<div class="empty">No recent events match this log type.</div>`;
}

function renderEvents(data) {
  renderEventRows(data.recent_events || []);
}

async function refreshEvents() {
  const filter = els.eventFilter.value;
  els.events.innerHTML = `<div class="empty">Loading ${escapeHtml(filter || "recent")} events.</div>`;
  try {
    const params = new URLSearchParams({ limit: "100" });
    if (filter) params.set("log_type", filter);
    renderEventRows(await getJson(`/api/zeek/events?${params.toString()}`));
  } catch (error) {
    els.events.innerHTML = `<div class="empty">${escapeHtml(error.message)}</div>`;
  }
}

function render(data) {
  renderOverview(data);
  renderTls(data);
  renderFiles(data);
  renderDnsHttp(data);
  renderEvents(data);
}

async function refresh() {
  els.refresh.disabled = true;
  els.updated.textContent = "Refreshing";
  try {
    telemetry = await getJson("/api/zeek/telemetry?limit=100");
    render(telemetry);
    els.updated.textContent = `Updated ${new Date().toLocaleTimeString()}`;
  } catch (error) {
    els.updated.textContent = "Zeek API error";
    els.checkpoints.innerHTML = `<div class="empty">${escapeHtml(error.message)}</div>`;
  } finally {
    els.refresh.disabled = false;
  }
}

document.querySelectorAll("[data-zeek-view]").forEach((button) => {
  button.addEventListener("click", () => {
    const selected = button.dataset.zeekView;
    document.querySelectorAll("[data-zeek-view]").forEach((item) => item.classList.toggle("selected", item === button));
    document.querySelectorAll(".zeek-view").forEach((view) => { view.hidden = view.id !== `zeek-view-${selected}`; });
  });
});

els.eventFilter.addEventListener("change", refreshEvents);
els.refresh.addEventListener("click", refresh);
refresh();

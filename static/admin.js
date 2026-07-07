const els = {
  updated: document.querySelector("#admin-updated"),
  aiModelForm: document.querySelector("#ai-model-form"),
  profileName: document.querySelector("#ai-profile-name"),
  profileUid: document.querySelector("#ai-profile-uid"),
  profileStatus: document.querySelector("#ai-profile-status"),
  profileNotes: document.querySelector("#ai-profile-notes"),
  profiles: document.querySelector("#ai-profiles"),
  newProfile: document.querySelector("#new-ai-profile"),
  aiModelHost: document.querySelector("#ai-model-host"),
  aiModelName: document.querySelector("#ai-model-name"),
  aiModelProvider: document.querySelector("#ai-model-provider"),
  aiModelNames: document.querySelector("#ai-model-suggestions"),
  aiModelTimeout: document.querySelector("#ai-model-timeout"),
  aiModelStatus: document.querySelector("#ai-model-admin-status"),
  aiModelSummary: document.querySelector("#ai-model-summary"),
  testAiModel: document.querySelector("#test-ai-model-admin"),
  systemModeForm: document.querySelector("#system-mode-form"),
  systemModeSelect: document.querySelector("#system-mode-select"),
  systemModeDescription: document.querySelector("#system-mode-description"),
  systemModeStatus: document.querySelector("#system-mode-status"),
  firewallTimeout: document.querySelector("#firewall-timeout"),
  firewallCommands: document.querySelector("#firewall-commands"),
  firewallCandidates: document.querySelector("#firewall-candidates"),
  firewallBlocks: document.querySelector("#firewall-blocks"),
  firewallHistory: document.querySelector("#firewall-history"),
  emailForm: document.querySelector("#email-notification-form"),
  emailEnabled: document.querySelector("#email-enabled"),
  emailSender: document.querySelector("#email-sender"),
  emailAppPassword: document.querySelector("#email-app-password"),
  emailPasswordStatus: document.querySelector("#email-password-status"),
  emailRecipients: document.querySelector("#email-recipients"),
  emailCooldown: document.querySelector("#email-cooldown"),
  emailDashboardUrl: document.querySelector("#email-dashboard-url"),
  emailStatus: document.querySelector("#email-notification-status"),
  emailTest: document.querySelector("#test-email-notifications"),
  notificationEvents: document.querySelector("#notification-events"),
  assetForm: document.querySelector("#admin-asset-form"),
  assetId: document.querySelector("#admin-asset-id"),
  assetIp: document.querySelector("#admin-asset-ip"),
  assetName: document.querySelector("#admin-asset-name"),
  assetType: document.querySelector("#admin-asset-type"),
  assetInterface: document.querySelector("#admin-asset-interface"),
  assetScore: document.querySelector("#admin-asset-score"),
  assetStatus: document.querySelector("#admin-asset-status"),
  assetFunction: document.querySelector("#admin-asset-function"),
  assetNotes: document.querySelector("#admin-asset-notes"),
  assetSubmit: document.querySelector("#admin-asset-submit"),
  assetCancel: document.querySelector("#admin-asset-cancel"),
  assets: document.querySelector("#admin-assets"),
  tools: document.querySelector("#admin-tools"),
  pythonPackages: document.querySelector("#admin-python-packages"),
  paths: document.querySelector("#admin-paths")
};

let state = { assets: [], types: [], network: {}, aiProfiles: [], activeProfileUid: "", modes: [] };

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
  if (Array.isArray(detail)) return detail.map((item) => item.msg || JSON.stringify(item)).join("; ");
  return JSON.stringify(detail);
}

function label(value) {
  if (!value) return "Unknown";
  return value.replaceAll("_", " ").replace(/\b\w/g, (char) => char.toUpperCase());
}

function setStatus(element, kind, text) {
  element.className = `connection-status ${kind || ""}`.trim();
  element.textContent = text;
}

function renderAiModel(settings) {
  const aiModel = settings.ai_model || {};
  const profiles = settings.ai_profiles || {};
  state.aiProfiles = profiles.items || [];
  state.activeProfileUid = profiles.active_uid || aiModel.active_profile_uid || "";
  const activeProfile = state.aiProfiles.find((profile) => profile.uid === state.activeProfileUid) || {};
  els.profileName.value = activeProfile.name || `${aiModel.provider || "ai"}:${aiModel.model || ""}`;
  els.profileUid.value = state.activeProfileUid || "";
  els.profileStatus.value = activeProfile.status || "active";
  els.profileNotes.value = activeProfile.notes || "";
  els.aiModelHost.value = aiModel.host || "";
  els.aiModelName.value = aiModel.model || "";
  els.aiModelProvider.value = aiModel.provider || "";
  els.aiModelTimeout.value = aiModel.timeout_seconds || 90;
  els.aiModelNames.innerHTML = (aiModel.model_suggestions || []).map((model) => `
    <option value="${model}"></option>
  `).join("");
  els.aiModelSummary.innerHTML = `
    <div class="list-item">
      <div class="row tight">
        <strong>Selected AI profile</strong>
        <span>${state.activeProfileUid || "no uid"}</span>
      </div>
      <p>${activeProfile.name || "Current model"} · ${aiModel.provider || "auto"}:${aiModel.model || "not configured"}</p>
      <p>${aiModel.host || "No AI service URL configured"}</p>
      <small>Timeout ${aiModel.timeout_seconds || 90}s. New AI logs are stamped with this profile UID and run ID.</small>
    </div>
  `;
  renderAiProfiles();
}

function renderAiProfiles() {
  els.profiles.innerHTML = `
    <div class="list-item">
      <div class="row tight">
        <strong>Saved AI profiles</strong>
        <span>${state.aiProfiles.length}</span>
      </div>
      <p>Select one before a test run so future AI logs can be compared by UID.</p>
    </div>
    ${state.aiProfiles.map((profile) => `
      <div
        class="list-item ai-profile ${profile.uid === state.activeProfileUid ? "active" : ""} ${profile.status === "inactive" ? "inactive" : ""}"
        ${profile.status === "active" ? `data-select-ai-profile="${profile.uid}" role="button" tabindex="0"` : ""}
      >
        <div class="row tight">
          <strong>${profile.name}</strong>
          <span class="status-pill ${profile.uid === state.activeProfileUid ? "active" : profile.status === "inactive" ? "inactive" : ""}">
            ${profile.uid === state.activeProfileUid ? "active / selected" : profile.status}
          </span>
        </div>
        <p>${profile.provider}:${profile.model}</p>
        <small>${profile.uid} · ${profile.host} · timeout ${profile.timeout_seconds || 90}s</small>
        ${profile.notes ? `<small>${profile.notes}</small>` : ""}
        <div class="asset-admin-actions">
          <button class="text-button" type="button" data-edit-ai-profile="${profile.uid}">Edit</button>
          <button class="text-button" type="button" data-select-ai-profile="${profile.uid}" ${profile.status === "inactive" || profile.uid === state.activeProfileUid ? "disabled" : ""}>
            ${profile.uid === state.activeProfileUid ? "Selected" : "Select"}
          </button>
        </div>
      </div>
    `).join("")}
  `;
}

function renderAssetTypes(types) {
  const current = els.assetType.value;
  els.assetType.innerHTML = types.map((type) => `
    <option value="${type.value}" data-score="${type.default_score}">
      ${type.label} (${type.default_score})
    </option>
  `).join("");
  if (current) els.assetType.value = current;
}

function renderAssets(payload) {
  state.assets = payload.items || [];
  state.types = payload.types || [];
  renderAssetTypes(state.types);

  els.assets.innerHTML = state.assets.map((asset) => `
    <div class="list-item asset-item admin-asset ${asset.status === "inactive" ? "inactive" : "active"}">
      <div class="row tight">
        <strong>${asset.name}</strong>
        <span class="status-pill ${asset.status === "inactive" ? "inactive" : "active"}">${asset.status}</span>
      </div>
      <p>${asset.ip_address} · ${label(asset.device_type)} · ${asset.network_interface || state.network.internal_interface || "ens37"}</p>
      <small>Score ${asset.asset_score} · ${asset.function || "No function"}${asset.notes ? ` · ${asset.notes}` : ""}</small>
      <div class="asset-admin-actions">
        <button class="text-button" type="button" data-edit-asset="${asset.id}">Edit</button>
        <button class="text-button" type="button" data-toggle-asset="${asset.id}">
          ${asset.status === "inactive" ? "Reactivate" : "Deactivate"}
        </button>
        <button class="text-button danger-button" type="button" data-delete-asset="${asset.id}">Delete</button>
      </div>
    </div>
  `).join("") || `<div class="empty">No machines registered yet.</div>`;
}

function renderSystemControls(settings) {
  const system = settings.system || {};
  const firewall = settings.firewall || {};
  state.modes = system.available_modes || [];
  const mode = system.mode || "alert_only";
  els.systemModeSelect.value = mode;
  const selected = state.modes.find((item) => item.value === mode);
  els.systemModeDescription.textContent = selected?.description || "Select how the system handles dangerous decisions.";
  els.firewallTimeout.value = `${firewall.block_timeout_seconds || 3600} seconds`;
  els.firewallCommands.innerHTML = `
    ${renderFirewallRuntime(firewall.runtime || {})}
    <div class="list-item">
      <div class="row tight">
        <strong>firewalld setup</strong>
        <span>${firewall.provider || "firewalld"}</span>
      </div>
      <p>Run these on the Security VM before using Prevention mode.</p>
      ${(firewall.setup_commands || []).map((command) => `
        <code class="command-line">${command}</code>
        <button class="text-button" type="button" data-copy-command="${encodeURIComponent(command)}">Copy Command</button>
      `).join("")}
    </div>
  `;
  renderFirewallCandidates(firewall.candidates || []);
  renderFirewallBlocks(firewall.blocks || []);
  renderFirewallHistory(firewall.history || []);
}

function renderNotifications(settings) {
  const notifications = settings.notifications || {};
  const email = notifications.email || {};
  els.emailEnabled.checked = Boolean(email.enabled);
  els.emailSender.value = email.sender || "";
  els.emailAppPassword.value = "";
  if (email.app_password_configured) {
    const lengthText = email.app_password_length ? ` Saved length: ${email.app_password_length}/16.` : "";
    els.emailPasswordStatus.textContent = `App password saved. Leave blank to keep it.${lengthText}`;
  } else {
    els.emailPasswordStatus.textContent = "No app password saved.";
  }
  els.emailRecipients.value = (email.recipients || []).join("\n");
  els.emailCooldown.value = email.cooldown_minutes ?? 15;
  els.emailDashboardUrl.value = email.dashboard_base_url || "";
  renderNotificationEvents(notifications.events || []);
}

function renderNotificationEvents(events) {
  els.notificationEvents.innerHTML = `
    <div class="list-item">
      <div class="row tight">
        <strong>Email notification history</strong>
        <span>${events.length}</span>
      </div>
      <p>Sent, failed, and skipped Gmail alert attempts.</p>
    </div>
    ${events.map((event) => `
      <div class="list-item notification-event ${event.status || ""}">
        <div class="row tight">
          <strong>${event.status || "unknown"}</strong>
          <span>${event.created_at || "unknown time"}</span>
        </div>
        <p>${event.subject || "No subject"}</p>
        <small>${event.recipient || "No recipient"}${event.final_score ? ` · score ${event.final_score}` : ""}</small>
        ${event.error ? `<small>${event.error}</small>` : ""}
      </div>
    `).join("") || `<div class="empty">No notification attempts yet.</div>`}
  `;
}

function renderFirewallRuntime(runtime) {
  const rules = runtime.rich_rules || [];
  const permissionNeeded = (runtime.errors || []).some((error) => String(error).includes("password is required"));
  return `
    <div class="list-item firewall-runtime ${runtime.running ? "active" : "inactive"}">
      <div class="row tight">
        <strong>firewalld status</strong>
        <span class="status-pill ${runtime.running ? "active" : "inactive"}">${runtime.running ? "running" : "not running"}</span>
      </div>
      <p>Service ${runtime.service_state || "unknown"} · firewall-cmd ${runtime.firewall_state || "unknown"} · ${runtime.rule_count || 0} rich rules</p>
      ${permissionNeeded ? `<small>Permission needed: run the one-time sudoers command below so the dashboard can use firewall-cmd without repeated password prompts.</small>` : ""}
      ${rules.length ? `
        <div class="mini-list dense">
          ${rules.map((rule) => `<code class="command-line">${rule}</code>`).join("")}
        </div>
      ` : `<small>No active rich rules reported by firewalld.</small>`}
      ${(runtime.errors || []).map((error) => `<small>${error}</small>`).join("")}
    </div>
  `;
}

function renderFirewallHistory(history) {
  els.firewallHistory.innerHTML = `
    <div class="list-item">
      <div class="row tight">
        <strong>Firewall decision history</strong>
        <span>${history.length}</span>
      </div>
      <p>Released blocks, marked-safe decisions, and previous enforcement attempts.</p>
    </div>
    ${history.map((item) => `
      <div class="list-item firewall-history-item ${item.history_type === "marked_safe" ? "safe" : item.status === "released" ? "released" : "active"}">
        <div class="row tight">
          <strong>${item.ip_address || "unknown IP"}</strong>
          <span>${item.history_type === "marked_safe" ? "marked safe" : item.status || "history"}</span>
        </div>
        <p>${label(item.detection_type)} · ${item.src_ip || "unknown"} -> ${item.dest_ip || "unknown"}</p>
        <small>${item.signature || item.reason || "No signature recorded"}</small>
        <small>${item.direction || "n/a"} · created ${item.created_at || "unknown"}${item.released_at ? ` · released ${item.released_at}` : ""}</small>
        ${item.release_reason ? `<small>${item.release_reason}</small>` : ""}
      </div>
    `).join("") || `<div class="empty">No firewall history yet.</div>`}
  `;
}

function renderFirewallCandidates(candidates) {
  els.firewallCandidates.innerHTML = `
    <div class="list-item">
      <div class="row tight">
        <strong>Dangerous detections awaiting enforcement</strong>
        <span>${candidates.length}</span>
      </div>
      <p>Detection mode queues high-risk would-block decisions here so an analyst can enforce or mark safe.</p>
    </div>
    ${candidates.map((candidate) => `
      <div class="list-item firewall-candidate">
        <div class="row tight">
          <strong>${candidate.target_ip}</strong>
          <span>score ${candidate.final_score}</span>
        </div>
        <p>${label(candidate.detection_type)} · ${candidate.src_ip || "unknown"} -> ${candidate.dest_ip || "unknown"}</p>
        <small>${candidate.signature || "No signature recorded"}</small>
        <small>${candidate.final_classification} · ${candidate.final_action} · ${candidate.response_created_at || "unknown time"}</small>
        <div class="asset-admin-actions">
          <button class="text-button danger-button" type="button" data-enforce-firewall="${candidate.response_id}">Enforce Block</button>
          <button class="text-button" type="button" data-safe-candidate="${candidate.response_id}">Mark Safe</button>
        </div>
      </div>
    `).join("") || `<div class="empty">No dangerous detections are waiting for manual enforcement.</div>`}
  `;
}

function renderFirewallBlocks(blocks) {
  els.firewallBlocks.innerHTML = `
    <div class="list-item">
      <div class="row tight">
        <strong>Active firewall blocks</strong>
        <span>${blocks.length}</span>
      </div>
      <p>Use unblock for a one-time release, or mark safe to release and add an allowlist entry.</p>
    </div>
    ${blocks.map((block) => `
      <div class="list-item firewall-block">
        <div class="row tight">
          <strong>${block.ip_address}</strong>
          <span>${block.status}</span>
        </div>
        <p>${label(block.detection_type)} · ${block.src_ip || "unknown"} -> ${block.dest_ip || "unknown"}</p>
        <small>${block.signature || block.reason || "No signature recorded"}</small>
        <small>${block.direction || "source"} · expires ${block.expires_at || "when firewalld timeout ends"}</small>
        <div class="asset-admin-actions">
          <button class="text-button" type="button" data-unblock-firewall="${block.id}">Unblock</button>
          <button class="text-button" type="button" data-safe-firewall="${block.id}">Mark Safe</button>
        </div>
      </div>
    `).join("") || `<div class="empty">No active firewalld blocks.</div>`}
  `;
}

function renderTools(tools) {
  els.tools.innerHTML = tools.map((tool) => `
    <div class="list-item tool-item ${tool.status || (tool.installed ? "ready" : "missing")}">
      <div class="row tight">
        <strong>${tool.name}</strong>
        <span>${toolStatusLabel(tool)}</span>
      </div>
      <p>${tool.binary}</p>
      <small>${tool.version ? `Version: ${tool.version}` : tool.notes || "Version not detected"}</small>
      <small>${tool.path || "Not found on PATH"}</small>
      ${toolAction(tool)}
    </div>
  `).join("") || `<div class="empty">No tool status returned.</div>`;
}

function toolStatusLabel(tool) {
  if (tool.status === "permission_limited") return "permission needed";
  if (tool.installed) return "installed";
  return "missing";
}

function toolAction(tool) {
  const command = tool.fix_command || (tool.installed ? tool.update_command : tool.install_command);
  if (!command) return "";
  const label = tool.fix_command ? "Copy Permission Fix" : `Copy ${tool.installed ? "Update" : "Install"} Command`;
  return `
    <details class="command-details">
      <summary>${tool.fix_command ? "Permission fix" : tool.installed ? "Update command" : "Install command"}</summary>
      <code class="command-line">${command}</code>
      ${tool.after_fix && tool.fix_command ? `<small>${tool.after_fix}</small>` : ""}
      <button class="text-button" type="button" data-copy-command="${encodeURIComponent(command)}" data-copy-label="${label}">
        ${label}
      </button>
    </details>
  `;
}

async function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(text);
    return true;
  }

  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.setAttribute("readonly", "");
  textarea.style.position = "fixed";
  textarea.style.left = "-9999px";
  document.body.appendChild(textarea);
  textarea.select();
  textarea.setSelectionRange(0, textarea.value.length);
  let copied = false;
  try {
    copied = document.execCommand("copy");
  } finally {
    document.body.removeChild(textarea);
  }
  return copied;
}

function renderPythonPackages(packages) {
  els.pythonPackages.innerHTML = packages.map((pkg) => `
    <div class="list-item tool-item ${pkg.installed ? "ready" : "missing"}">
      <div class="row tight">
        <strong>${pkg.name}</strong>
        <span>${pkg.installed ? "installed" : "missing"}</span>
      </div>
      <p>${pkg.module}</p>
      <small>${pkg.version || "Version not detected"} · ${pkg.source}</small>
      <code class="command-line">${pkg.installed ? pkg.update_command : pkg.install_command}</code>
      <button class="text-button" type="button" data-copy-command="${encodeURIComponent(pkg.installed ? pkg.update_command : pkg.install_command)}">
        Copy ${pkg.installed ? "Update" : "Install"} Command
      </button>
    </div>
  `).join("") || `<div class="empty">No Python package status returned.</div>`;
}

function renderPaths(settings) {
  const network = settings.network || {};
  els.paths.innerHTML = `
    <div class="list-item">
      <div class="row tight">
        <strong>Config file</strong>
        <span>YAML</span>
      </div>
      <p>${settings.config_path || "config.yaml"}</p>
    </div>
    <div class="list-item">
      <div class="row tight">
        <strong>SQLite database</strong>
        <span>local</span>
      </div>
      <p>${settings.database_path || "security_vm.db"}</p>
    </div>
    <div class="list-item">
      <div class="row tight">
        <strong>Internal interface</strong>
        <span>${network.internal_interface || "ens37"}</span>
      </div>
      <p>Used as the default interface for registered machines.</p>
    </div>
    <div class="list-item">
      <div class="row tight">
        <strong>Suricata EVE JSON</strong>
        <span>alert source</span>
      </div>
      <p>${network.suricata_eve_json_path || "/var/log/suricata/eve.json"}</p>
    </div>
    <div class="list-item">
      <div class="row tight">
        <strong>Rolling PCAP directory</strong>
        <span>capture files</span>
      </div>
      <p>${network.pcap_rolling_dir || "/var/log/pcap"}</p>
    </div>
  `;
}

async function refresh() {
  try {
    const settings = await getJson("/api/admin/settings");
    state.network = settings.network || {};
    renderAiModel(settings);
    renderSystemControls(settings);
    renderNotifications(settings);
    renderAssets(settings.assets || {});
    renderTools(settings.tools || []);
    renderPythonPackages(settings.python_packages || []);
    renderPaths(settings);
    els.updated.textContent = new Date().toLocaleTimeString();
  } catch (error) {
    els.updated.textContent = "Admin API error";
    setStatus(els.aiModelStatus, "error", error.message);
  }
}

function assetPayloadFromForm() {
  const score = els.assetScore.value;
  return {
    ip_address: els.assetIp.value,
    name: els.assetName.value,
    device_type: els.assetType.value,
    network_interface: els.assetInterface.value,
    asset_score: score === "" ? null : Number(score),
    status: els.assetStatus.value,
    function: els.assetFunction.value,
    notes: els.assetNotes.value
  };
}

function resetAssetForm() {
  els.assetForm.reset();
  els.assetId.value = "";
  els.assetSubmit.textContent = "Add Inventory Record";
  const selected = els.assetType.selectedOptions[0];
  els.assetScore.value = selected ? selected.dataset.score : "";
  els.assetInterface.placeholder = state.network.internal_interface || "ens37";
}

function editAsset(assetId) {
  const asset = state.assets.find((item) => String(item.id) === String(assetId));
  if (!asset) return;
  els.assetId.value = asset.id;
  els.assetIp.value = asset.ip_address || "";
  els.assetName.value = asset.name || "";
  els.assetType.value = asset.device_type || "unknown";
  els.assetInterface.value = asset.network_interface || "";
  els.assetScore.value = asset.asset_score ?? "";
  els.assetStatus.value = asset.status || "active";
  els.assetFunction.value = asset.function || "";
  els.assetNotes.value = asset.notes || "";
  els.assetSubmit.textContent = "Save Inventory Changes";
  els.assetForm.scrollIntoView({ behavior: "smooth", block: "start" });
}

async function toggleAssetStatus(assetId) {
  const asset = state.assets.find((item) => String(item.id) === String(assetId));
  if (!asset) return;
  const nextStatus = asset.status === "inactive" ? "active" : "inactive";
  await sendJson(`/api/admin/assets/${asset.id}`, "PUT", {
    ip_address: asset.ip_address,
    name: asset.name,
    device_type: asset.device_type,
    network_interface: asset.network_interface,
    asset_score: asset.asset_score,
    status: nextStatus,
    function: asset.function || "",
    notes: asset.notes || ""
  });
  await refresh();
}

async function deleteAsset(assetId) {
  const asset = state.assets.find((item) => String(item.id) === String(assetId));
  const name = asset?.name || `asset ${assetId}`;
  const confirmed = window.confirm(`Delete ${name} permanently? Use inactive status instead if you need to keep it for asset tracking.`);
  if (!confirmed) return;
  await sendJson(`/api/admin/assets/${assetId}`, "DELETE");
  if (els.assetId.value === String(assetId)) resetAssetForm();
  await refresh();
}

async function saveSystemMode() {
  const mode = els.systemModeSelect.value;
  await sendJson("/api/admin/system-mode", "POST", { mode });
  setStatus(els.systemModeStatus, mode === "prevention" ? "warn" : "ok", `System mode saved as ${mode}. The ingest loop reloads config before each decision.`);
  await refresh();
}

async function unblockFirewall(blockId) {
  const analyst = window.prompt("Analyst name for unblock:", "admin") || "admin";
  const reason = window.prompt("Reason for unblock:", "Manual unblock from admin console") || "Manual unblock from admin console";
  const result = await sendJson(`/api/admin/firewall-blocks/${blockId}/unblock`, "POST", { analyst_name: analyst, reason });
  window.alert(`Unblock result: ${result.status}`);
  await refresh();
}

async function markFirewallSafe(blockId) {
  const analyst = window.prompt("Analyst name for safe decision:", "admin") || "admin";
  const reason = window.prompt("Why is this IP safe?", "Trusted device or approved traffic") || "Trusted device or approved traffic";
  const result = await sendJson(`/api/admin/firewall-blocks/${blockId}/mark-safe`, "POST", {
    analyst_name: analyst,
    reason,
    safe_duration_hours: 24 * 365
  });
  window.alert(`Marked safe. Unblock result: ${result.unblock_status}`);
  await refresh();
}

async function enforceFirewallCandidate(responseId) {
  const analyst = window.prompt("Analyst name for enforcement:", "admin") || "admin";
  const reason = window.prompt("Reason for enforcing this block:", "Manual enforcement from detection queue") || "Manual enforcement from detection queue";
  const result = await sendJson(`/api/admin/firewall-candidates/${responseId}/enforce`, "POST", { analyst_name: analyst, reason });
  window.alert(`Enforcement result: ${result.status}`);
  await refresh();
}

async function markFirewallCandidateSafe(responseId) {
  const analyst = window.prompt("Analyst name for safe decision:", "admin") || "admin";
  const reason = window.prompt("Why should this traffic be allowed?", "Trusted device or approved traffic") || "Trusted device or approved traffic";
  const result = await sendJson(`/api/admin/firewall-candidates/${responseId}/mark-safe`, "POST", {
    analyst_name: analyst,
    reason,
    safe_duration_hours: 24 * 365
  });
  window.alert(`Candidate marked ${result.status}.`);
  await refresh();
}

function emailNotificationPayloadFromForm() {
  return {
    enabled: els.emailEnabled.checked,
    sender: els.emailSender.value,
    app_password: els.emailAppPassword.value,
    recipients: els.emailRecipients.value,
    cooldown_minutes: Number(els.emailCooldown.value || 15),
    dashboard_base_url: els.emailDashboardUrl.value
  };
}

async function saveEmailNotifications() {
  const payload = emailNotificationPayloadFromForm();
  const result = await sendJson("/api/admin/notifications/email", "POST", payload);
  setStatus(els.emailStatus, "ok", `Gmail alerts ${result.email.enabled ? "enabled" : "disabled"}.`);
  await refresh();
}

async function testEmailNotifications() {
  const payload = emailNotificationPayloadFromForm();
  await sendJson("/api/admin/notifications/email", "POST", payload);
  const result = await sendJson("/api/admin/notifications/email/test", "POST", payload);
  setStatus(els.emailStatus, "ok", `Test email sent to ${(result.recipients || []).join(", ")}.`);
  await refresh();
}

async function saveAiModel() {
  const payload = aiProfilePayloadFromForm();
  const uid = els.profileUid.value;
  if (uid) {
    await sendJson(`/api/admin/ai-profiles/${encodeURIComponent(uid)}`, "PUT", payload);
    if (payload.status === "active") {
      await sendJson(`/api/admin/ai-profiles/${encodeURIComponent(uid)}/select`, "POST");
    }
  } else {
    await sendJson("/api/admin/ai-profiles", "POST", payload);
  }
  setStatus(els.aiModelStatus, "ok", payload.status === "active" ? "AI profile saved and selected." : "AI profile saved as inactive.");
  await refresh();
}

function aiProfilePayloadFromForm() {
  return {
    name: els.profileName.value,
    host: els.aiModelHost.value,
    model: els.aiModelName.value,
    provider: els.aiModelProvider.value,
    timeout_seconds: Number(els.aiModelTimeout.value || 90),
    status: els.profileStatus.value,
    notes: els.profileNotes.value
  };
}

async function saveNewAiProfile() {
  const payload = aiProfilePayloadFromForm();
  await sendJson("/api/admin/ai-profiles", "POST", payload);
  setStatus(els.aiModelStatus, "ok", payload.status === "active" ? "New AI profile created and selected." : "New inactive AI profile created.");
  await refresh();
}

async function selectAiProfile(uid) {
  await sendJson(`/api/admin/ai-profiles/${encodeURIComponent(uid)}/select`, "POST");
  setStatus(els.aiModelStatus, "ok", "AI profile selected. New AI logs will use that UID.");
  await refresh();
}

function editAiProfile(uid) {
  const profile = state.aiProfiles.find((item) => item.uid === uid);
  if (!profile) return;
  els.profileName.value = profile.name || "";
  els.profileUid.value = profile.uid || "";
  els.profileStatus.value = profile.status || "active";
  els.profileNotes.value = profile.notes || "";
  els.aiModelHost.value = profile.host || "";
  els.aiModelName.value = profile.model || "";
  els.aiModelProvider.value = profile.provider || "";
  els.aiModelTimeout.value = profile.timeout_seconds || 90;
  els.aiModelForm.scrollIntoView({ behavior: "smooth", block: "start" });
}

els.aiModelForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await saveAiModel();
  } catch (error) {
    setStatus(els.aiModelStatus, "error", error.message);
  }
});

els.testAiModel.addEventListener("click", async () => {
  try {
    await saveAiModel();
    const status = await getJson("/api/ai-status");
    if (status.ok) {
      setStatus(
        els.aiModelStatus,
        "ok",
        `AI profile ${status.ai_profile_uid || "unknown"} reachable in ${status.elapsed_ms ?? 0}ms. Models: ${(status.models || []).join(", ") || "none returned"}`
      );
    } else {
      setStatus(els.aiModelStatus, "error", status.error || "AI model check failed");
    }
  } catch (error) {
    setStatus(els.aiModelStatus, "error", error.message);
  }
});

els.newProfile.addEventListener("click", async () => {
  try {
    await saveNewAiProfile();
  } catch (error) {
    setStatus(els.aiModelStatus, "error", error.message);
  }
});

els.systemModeForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await saveSystemMode();
  } catch (error) {
    setStatus(els.systemModeStatus, "error", error.message);
  }
});

els.emailForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await saveEmailNotifications();
  } catch (error) {
    setStatus(els.emailStatus, "error", error.message);
  }
});

els.emailTest.addEventListener("click", async () => {
  try {
    await testEmailNotifications();
  } catch (error) {
    setStatus(els.emailStatus, "error", error.message);
    await refresh().catch(() => {});
  }
});

els.systemModeSelect.addEventListener("change", () => {
  const selected = state.modes.find((item) => item.value === els.systemModeSelect.value);
  els.systemModeDescription.textContent = selected?.description || "Select how the system handles dangerous decisions.";
});

els.assetForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const assetId = els.assetId.value;
  try {
    if (assetId) {
      await sendJson(`/api/admin/assets/${assetId}`, "PUT", assetPayloadFromForm());
    } else {
      const payload = assetPayloadFromForm();
      delete payload.status;
      await sendJson("/api/assets", "POST", payload);
    }
    resetAssetForm();
    await refresh();
  } catch (error) {
    window.alert(error.message);
  }
});

els.assetCancel.addEventListener("click", resetAssetForm);

els.assetType.addEventListener("change", () => {
  const selected = els.assetType.selectedOptions[0];
  els.assetScore.value = selected ? selected.dataset.score : "";
});

document.addEventListener("click", (event) => {
  const button = event.target.closest("button");
  const assetId = event.target.dataset.editAsset;
  if (assetId) editAsset(assetId);
  const toggleId = event.target.dataset.toggleAsset;
  if (toggleId) {
    toggleAssetStatus(toggleId).catch((error) => window.alert(error.message));
  }
  const deleteId = event.target.dataset.deleteAsset;
  if (deleteId) {
    deleteAsset(deleteId).catch((error) => window.alert(error.message));
  }
  const unblockId = event.target.dataset.unblockFirewall;
  if (unblockId) {
    unblockFirewall(unblockId).catch((error) => window.alert(error.message));
  }
  const safeId = event.target.dataset.safeFirewall;
  if (safeId) {
    markFirewallSafe(safeId).catch((error) => window.alert(error.message));
  }
  const enforceId = event.target.dataset.enforceFirewall;
  if (enforceId) {
    enforceFirewallCandidate(enforceId).catch((error) => window.alert(error.message));
  }
  const safeCandidateId = event.target.dataset.safeCandidate;
  if (safeCandidateId) {
    markFirewallCandidateSafe(safeCandidateId).catch((error) => window.alert(error.message));
  }
  const editProfileUid = event.target.dataset.editAiProfile;
  if (editProfileUid) {
    editAiProfile(editProfileUid);
    return;
  }
  const profileTarget = event.target.closest("[data-select-ai-profile]");
  const selectProfileUid = profileTarget && !button ? profileTarget.dataset.selectAiProfile : event.target.dataset.selectAiProfile;
  if (selectProfileUid) {
    selectAiProfile(selectProfileUid).catch((error) => setStatus(els.aiModelStatus, "error", error.message));
  }
  const command = event.target.dataset.copyCommand;
  if (command) {
    const originalLabel = event.target.dataset.copyLabel || event.target.textContent;
    const commandText = decodeURIComponent(command);
    copyText(commandText)
      .then((copied) => {
        if (!copied) {
          window.prompt("Copy this command:", commandText);
          return;
        }
        event.target.textContent = "Copied";
        window.setTimeout(() => {
          event.target.textContent = originalLabel;
        }, 1400);
      })
      .catch(() => window.prompt("Copy this command:", commandText));
  }
});

document.addEventListener("keydown", (event) => {
  if (!["Enter", " "].includes(event.key)) return;
  const profileTarget = event.target.closest("[data-select-ai-profile]");
  if (!profileTarget) return;
  event.preventDefault();
  selectAiProfile(profileTarget.dataset.selectAiProfile).catch((error) => setStatus(els.aiModelStatus, "error", error.message));
});

refresh();

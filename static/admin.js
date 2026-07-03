const els = {
  updated: document.querySelector("#admin-updated"),
  ollamaForm: document.querySelector("#ollama-form"),
  profileName: document.querySelector("#ai-profile-name"),
  profileUid: document.querySelector("#ai-profile-uid"),
  profileStatus: document.querySelector("#ai-profile-status"),
  profileNotes: document.querySelector("#ai-profile-notes"),
  profiles: document.querySelector("#ai-profiles"),
  newProfile: document.querySelector("#new-ai-profile"),
  ollamaHost: document.querySelector("#ollama-host"),
  ollamaModel: document.querySelector("#ollama-model"),
  ollamaProvider: document.querySelector("#ollama-provider"),
  ollamaModels: document.querySelector("#ollama-models"),
  ollamaTimeout: document.querySelector("#ollama-timeout"),
  ollamaStatus: document.querySelector("#ollama-admin-status"),
  ollamaSummary: document.querySelector("#ollama-summary"),
  testOllama: document.querySelector("#test-ollama-admin"),
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

let state = { assets: [], types: [], network: {}, aiProfiles: [], activeProfileUid: "" };

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

function renderOllama(settings) {
  const ollama = settings.ollama || {};
  const profiles = settings.ai_profiles || {};
  state.aiProfiles = profiles.items || [];
  state.activeProfileUid = profiles.active_uid || ollama.active_profile_uid || "";
  const activeProfile = state.aiProfiles.find((profile) => profile.uid === state.activeProfileUid) || {};
  els.profileName.value = activeProfile.name || `${ollama.provider || "ai"}:${ollama.model || ""}`;
  els.profileUid.value = state.activeProfileUid || "";
  els.profileStatus.value = activeProfile.status || "active";
  els.profileNotes.value = activeProfile.notes || "";
  els.ollamaHost.value = ollama.host || "";
  els.ollamaModel.value = ollama.model || "";
  els.ollamaProvider.value = ollama.provider || "";
  els.ollamaTimeout.value = ollama.timeout_seconds || 90;
  els.ollamaModels.innerHTML = (ollama.model_suggestions || []).map((model) => `
    <option value="${model}"></option>
  `).join("");
  els.ollamaSummary.innerHTML = `
    <div class="list-item">
      <div class="row tight">
        <strong>Selected AI profile</strong>
        <span>${state.activeProfileUid || "no uid"}</span>
      </div>
      <p>${activeProfile.name || "Current model"} · ${ollama.provider || "auto"}:${ollama.model || "not configured"}</p>
      <p>${ollama.host || "No AI service URL configured"}</p>
      <small>Timeout ${ollama.timeout_seconds || 90}s. New AI logs are stamped with this profile UID and run ID.</small>
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
    renderOllama(settings);
    renderAssets(settings.assets || {});
    renderTools(settings.tools || []);
    renderPythonPackages(settings.python_packages || []);
    renderPaths(settings);
    els.updated.textContent = new Date().toLocaleTimeString();
  } catch (error) {
    els.updated.textContent = "Admin API error";
    setStatus(els.ollamaStatus, "error", error.message);
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
  els.assetSubmit.textContent = "Add Machine";
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
  els.assetSubmit.textContent = "Save Machine Changes";
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

async function saveOllama() {
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
  setStatus(els.ollamaStatus, "ok", payload.status === "active" ? "AI profile saved and selected." : "AI profile saved as inactive.");
  await refresh();
}

function aiProfilePayloadFromForm() {
  return {
    name: els.profileName.value,
    host: els.ollamaHost.value,
    model: els.ollamaModel.value,
    provider: els.ollamaProvider.value,
    timeout_seconds: Number(els.ollamaTimeout.value || 90),
    status: els.profileStatus.value,
    notes: els.profileNotes.value
  };
}

async function saveNewAiProfile() {
  const payload = aiProfilePayloadFromForm();
  await sendJson("/api/admin/ai-profiles", "POST", payload);
  setStatus(els.ollamaStatus, "ok", payload.status === "active" ? "New AI profile created and selected." : "New inactive AI profile created.");
  await refresh();
}

async function selectAiProfile(uid) {
  await sendJson(`/api/admin/ai-profiles/${encodeURIComponent(uid)}/select`, "POST");
  setStatus(els.ollamaStatus, "ok", "AI profile selected. New AI logs will use that UID.");
  await refresh();
}

function editAiProfile(uid) {
  const profile = state.aiProfiles.find((item) => item.uid === uid);
  if (!profile) return;
  els.profileName.value = profile.name || "";
  els.profileUid.value = profile.uid || "";
  els.profileStatus.value = profile.status || "active";
  els.profileNotes.value = profile.notes || "";
  els.ollamaHost.value = profile.host || "";
  els.ollamaModel.value = profile.model || "";
  els.ollamaProvider.value = profile.provider || "";
  els.ollamaTimeout.value = profile.timeout_seconds || 90;
  els.ollamaForm.scrollIntoView({ behavior: "smooth", block: "start" });
}

els.ollamaForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await saveOllama();
  } catch (error) {
    setStatus(els.ollamaStatus, "error", error.message);
  }
});

els.testOllama.addEventListener("click", async () => {
  try {
    await saveOllama();
    const status = await getJson("/api/ollama-status");
    if (status.ok) {
      setStatus(
        els.ollamaStatus,
        "ok",
        `AI profile ${status.ai_profile_uid || "unknown"} reachable in ${status.elapsed_ms ?? 0}ms. Models: ${(status.models || []).join(", ") || "none returned"}`
      );
    } else {
      setStatus(els.ollamaStatus, "error", status.error || "AI model check failed");
    }
  } catch (error) {
    setStatus(els.ollamaStatus, "error", error.message);
  }
});

els.newProfile.addEventListener("click", async () => {
  try {
    await saveNewAiProfile();
  } catch (error) {
    setStatus(els.ollamaStatus, "error", error.message);
  }
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
  const editProfileUid = event.target.dataset.editAiProfile;
  if (editProfileUid) {
    editAiProfile(editProfileUid);
    return;
  }
  const profileTarget = event.target.closest("[data-select-ai-profile]");
  const selectProfileUid = profileTarget && !button ? profileTarget.dataset.selectAiProfile : event.target.dataset.selectAiProfile;
  if (selectProfileUid) {
    selectAiProfile(selectProfileUid).catch((error) => setStatus(els.ollamaStatus, "error", error.message));
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
  selectAiProfile(profileTarget.dataset.selectAiProfile).catch((error) => setStatus(els.ollamaStatus, "error", error.message));
});

refresh();

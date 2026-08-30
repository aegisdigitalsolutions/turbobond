/* turbobond control panel.
 *
 * The user signs in; from there the page just reports what the gateway is
 * doing. Nothing here configures the network - every decision is made server
 * side, and this only renders state and offers overrides.
 */

"use strict";

const state = {
  csrf: "",
  lastLogSeq: 0,
  pollTimer: null,
  eventSource: null,
};

const $ = (id) => document.getElementById(id);

// ------------------------------------------------------------------ requests

async function api(path, options = {}) {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (state.csrf && options.method && options.method !== "GET") {
    headers["X-TurboBond-CSRF"] = state.csrf;
  }
  const response = await fetch(path, { credentials: "same-origin", ...options, headers });
  const text = await response.text();
  let body = null;
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = { detail: { message: text } };
    }
  }
  if (!response.ok) {
    const detail = body && body.detail ? body.detail : {};
    const error = new Error(detail.message || `request failed with ${response.status}`);
    error.status = response.status;
    error.remedy = detail.remedy || "";
    throw error;
  }
  return body;
}

// -------------------------------------------------------------------- views

function show(view) {
  for (const id of ["signin-view", "activating-view", "dashboard-view"]) {
    $(id).hidden = id !== view;
  }
}

// ------------------------------------------------------------------ sign in

async function bootstrap() {
  try {
    const info = await api("/api/bootstrap");
    $("version").textContent = `v${info.version}`;
    if (!info.enrolled) {
      $("signin-subtitle").textContent =
        "Choose a password to secure this gateway. Everything else is automatic.";
      $("password").setAttribute("autocomplete", "new-password");
      $("first-run").open = true;
    }
    if (info.router_host) $("router-host").placeholder = info.router_host;
  } catch {
    // The sign-in form still works if bootstrap fails; do not block on it.
  }

  // An existing session skips straight to the dashboard.
  try {
    const session = await api("/api/session");
    state.csrf = session.csrf;
    show("dashboard-view");
    startPolling();
  } catch {
    show("signin-view");
  }
}

function optionalValue(id) {
  const value = $(id).value.trim();
  return value === "" ? null : value;
}

function optionalNumber(id) {
  const value = $(id).value.trim();
  if (value === "") return null;
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : null;
}

async function signIn(event) {
  event.preventDefault();
  const button = $("signin-button");
  const errorBox = $("signin-error");
  errorBox.hidden = true;
  button.disabled = true;
  button.textContent = "Signing in...";

  try {
    const result = await api("/api/signin", {
      method: "POST",
      body: JSON.stringify({
        username: $("username").value.trim() || "admin",
        password: $("password").value,
        router_host: optionalValue("router-host"),
        router_password: optionalValue("router-password"),
        concentrator_host: optionalValue("concentrator-host"),
        concentrator_port: optionalNumber("concentrator-port"),
        shadowsocks_host: optionalValue("ss-host"),
        shadowsocks_port: optionalNumber("ss-port"),
        shadowsocks_password: optionalValue("ss-password"),
        shadowsocks_method: optionalValue("ss-method"),
        activate: true,
      }),
    });
    state.csrf = result.csrf;
    $("password").value = "";
    if (result.activation) {
      show("activating-view");
      followActivation();
    } else {
      show("dashboard-view");
      startPolling();
    }
  } catch (error) {
    errorBox.textContent = error.remedy ? `${error.message} — ${error.remedy}` : error.message;
    errorBox.hidden = false;
  } finally {
    button.disabled = false;
    button.textContent = "Sign in and activate";
  }
}

// --------------------------------------------------------------- activation

function followActivation() {
  if (state.eventSource) state.eventSource.close();
  const source = new EventSource("/api/activation/stream");
  state.eventSource = source;

  source.onmessage = (message) => {
    let event;
    try {
      event = JSON.parse(message.data);
    } catch {
      return;
    }
    if (event.done) {
      source.close();
      state.eventSource = null;
      show("dashboard-view");
      startPolling();
      return;
    }
    $("activating-phase").textContent = titleCase(event.phase || "working");
    $("activating-message").textContent = event.message || "";
    $("progress-bar").style.width = `${Math.round((event.fraction || 0) * 100)}%`;
  };

  source.onerror = () => {
    // The stream ends when activation finishes; fall back to polling.
    source.close();
    state.eventSource = null;
    show("dashboard-view");
    startPolling();
  };
}

function renderStages(stages) {
  const list = $("stage-list");
  list.innerHTML = "";
  for (const stage of stages || []) {
    const item = document.createElement("li");
    const failed = !stage.ok;
    item.className = failed ? "failed" : stage.degraded ? "degraded" : "ok";
    item.innerHTML =
      `<span class="stage-icon">${failed ? "x" : stage.degraded ? "!" : "+"}</span>` +
      `<span class="stage-phase">${escapeHtml(titleCase(stage.phase))}</span>` +
      `<span>${escapeHtml(stage.detail || "")}</span>`;
    list.appendChild(item);
  }
}

// ---------------------------------------------------------------- dashboard

function startPolling() {
  if (state.pollTimer) clearInterval(state.pollTimer);
  refresh();
  state.pollTimer = setInterval(refresh, 3000);
}

function stopPolling() {
  if (state.pollTimer) clearInterval(state.pollTimer);
  state.pollTimer = null;
}

async function refresh() {
  let status;
  try {
    status = await api("/api/status");
  } catch (error) {
    if (error.status === 401) {
      stopPolling();
      show("signin-view");
    }
    return;
  }

  renderPhase(status);
  renderBond(status);
  renderRoutes(status);
  renderLinks(status);
  renderRouter(status);
  renderSip(status);
  renderDevices(status);
  renderStages(status.stages);
  refreshLogs();
}

function renderPhase(status) {
  const pill = $("phase-pill");
  pill.textContent = status.phase;
  pill.className = "pill";
  if (status.phase === "active") pill.classList.add("active");
  else if (status.phase === "degraded") pill.classList.add("degraded");
  else if (status.phase === "failed") pill.classList.add("failed");
}

function renderBond(status) {
  const aggregate = status.aggregate || {};
  $("metric-uplinks").textContent = aggregate.uplinks ?? 0;
  $("metric-down").textContent = Math.round(aggregate.down_mbps ?? 0);
  $("metric-up").textContent = Math.round(aggregate.up_mbps ?? 0);
  $("metric-mode").textContent = status.bond_mode === "tunnel" ? "per-packet" : status.bond_mode === "ecmp" ? "per-flow" : "-";

  const note = $("bond-note");
  const bondStage = (status.stages || []).find((s) => s.phase === "bond");
  const text = bondStage && bondStage.data ? bondStage.data.note : "";
  note.textContent = text || "";
  note.hidden = !text;
}

function renderRoutes(status) {
  const container = $("route-switch");
  const selector = status.routes || {};
  const routes = selector.routes || [];
  container.innerHTML = "";

  for (const route of routes) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "route-option";
    if (route.active) button.classList.add("active");
    if (!route.available) button.classList.add("unavailable");
    button.disabled = !route.available;
    button.innerHTML =
      `<span class="route-dot"></span><span>` +
      `<span class="route-name">${escapeHtml(route.title || route.name)}</span>` +
      `<span class="route-desc">${escapeHtml(route.reason || describeRoute(route))}</span>` +
      `</span>`;
    button.addEventListener("click", () => selectRoute(route.name));
    container.appendChild(button);
  }

  if (!routes.length) {
    container.innerHTML = '<p class="hint">Routes appear once the bond is active.</p>';
  }
  $("route-detail").textContent = selector.switches
    ? `${selector.switches} failover(s) since activation`
    : selector.auto_failover === false
      ? "Automatic failover is off"
      : "Automatic failover is on";
}

function describeRoute(route) {
  const parts = [];
  if (route.rtt_ms) parts.push(`${route.rtt_ms.toFixed(0)} ms`);
  if (route.loss_pct) parts.push(`${route.loss_pct.toFixed(1)}% loss`);
  if (!parts.length) return route.healthy ? "Healthy" : "Waiting for a probe";
  return parts.join(" · ");
}

async function selectRoute(name) {
  try {
    await api("/api/routes/select", { method: "POST", body: JSON.stringify({ route: name }) });
    refresh();
  } catch (error) {
    console.warn("could not switch route:", error.message);
  }
}

function renderLinks(status) {
  const body = $("links-body");
  const links = (status.links && status.links.links) || [];
  const shares = (status.tunnel && status.tunnel.scheduler && status.tunnel.scheduler.share_estimate) || {};
  body.innerHTML = "";

  if (!links.length) {
    body.innerHTML = '<tr><td colspan="6" class="empty">No uplinks discovered yet</td></tr>';
    return;
  }

  for (const link of links) {
    const share = shares[link.name];
    const row = document.createElement("tr");
    row.innerHTML =
      `<td><strong>${escapeHtml(link.name)}</strong><br><span class="muted tiny">${escapeHtml(link.interface)}</span></td>` +
      `<td class="state-${escapeHtml(link.state)}">${escapeHtml(link.state)}${link.metered ? " (metered)" : ""}</td>` +
      `<td>${link.health.rtt_ms ? `${link.health.rtt_ms.toFixed(0)} ms` : "-"}</td>` +
      `<td>${link.health.loss_pct ? `${link.health.loss_pct.toFixed(1)}%` : "0%"}</td>` +
      `<td>${share !== undefined ? `${Math.round(share * 100)}%` : "-"}</td>` +
      `<td>${Math.round(link.downlink_mbps)} / ${Math.round(link.uplink_mbps)}</td>`;
    body.appendChild(row);
  }
}

function renderRouter(status) {
  // Prefer the live reading; the stage record is a snapshot from activation
  // time and would freeze signal strength and anything the app has since
  // changed on the router.
  const routerStage = (status.stages || []).find((s) => s.phase === "router");
  const snapshot = routerStage && routerStage.data ? routerStage.data.status || {} : {};
  const info = status.router && Object.keys(status.router).length ? status.router : snapshot;
  setKv("router-info", [
    ["Model", info.model || "not detected"],
    ["Firmware", info.firmware || "-"],
    ["Signed in", info.authenticated ? "yes" : "no", info.authenticated ? "good" : "warn"],
    ["WAN", info.wan_state || "-"],
    ["Carrier", info.carrier || "-"],
    ["Network", info.network_type || "-"],
    ["Bands", (info.bands || []).join(", ") || "-"],
    ["RSRP", info.rsrp !== null && info.rsrp !== undefined ? `${info.rsrp} dBm` : "-"],
    ["SINR", info.sinr !== null && info.sinr !== undefined ? `${info.sinr} dB` : "-"],
    ["SIP ALG", sipAlgLabel(info.sip_alg_enabled), info.sip_alg_enabled === false ? "good" : "warn"],
  ]);
}

function sipAlgLabel(value) {
  if (value === false) return "off";
  if (value === true) return "on (breaks SIP)";
  return "not exposed";
}

function renderSip(status) {
  const sip = status.sip || {};
  setKv("sip-info", [
    ["Backend", sip.backend || "-"],
    ["Rules applied", sip.applied ? "yes" : "no", sip.applied ? "good" : "bad"],
    ["Mode", sip.wide_open ? "wide open" : "stateful"],
    ["Signalling", (sip.signalling_ports || []).join(", ") || "-"],
    ["RTP range", sip.rtp_range || "-"],
    ["Kernel ALG", sip.alg_disabled ? "disabled" : "still active", sip.alg_disabled ? "good" : "warn"],
    ["Rules", String(sip.rules_installed ?? 0)],
  ]);
}

function renderDevices(status) {
  const body = $("devices-body");
  const devices = (status.devices && status.devices.devices) || [];
  body.innerHTML = "";

  if (!devices.length) {
    body.innerHTML = '<tr><td colspan="5" class="empty">No devices seen yet</td></tr>';
    return;
  }

  for (const device of devices) {
    const row = document.createElement("tr");
    row.innerHTML =
      `<td>${escapeHtml(device.name || device.mac || "unknown")}</td>` +
      `<td>${escapeHtml(device.ip || "-")}</td>` +
      `<td>${escapeHtml(device.connection || "-")}</td>` +
      `<td>${escapeHtml(device.route || "direct")}</td>` +
      `<td class="${device.bonded && device.online ? "state-up" : "state-down"}">` +
      `${device.online ? (device.bonded ? "bonded" : "online") : "offline"}</td>`;
    body.appendChild(row);
  }
}

function setKv(id, pairs) {
  const list = $(id);
  list.innerHTML = "";
  for (const [key, value, tone] of pairs) {
    const dt = document.createElement("dt");
    dt.textContent = key;
    const dd = document.createElement("dd");
    dd.textContent = value;
    if (tone) dd.className = tone;
    list.append(dt, dd);
  }
}

async function refreshLogs() {
  try {
    const data = await api(`/api/logs?after=${state.lastLogSeq}&limit=200`);
    const records = data.records || [];
    if (!records.length) return;
    const view = $("log-view");
    const atBottom = view.scrollTop + view.clientHeight >= view.scrollHeight - 40;
    for (const record of records) {
      state.lastLogSeq = Math.max(state.lastLogSeq, record.seq);
      const line = document.createElement("div");
      line.className = `lvl-${record.level}`;
      const stamp = new Date(record.ts * 1000).toLocaleTimeString();
      line.textContent = `${stamp}  ${record.level.padEnd(7)} ${record.message}`;
      view.appendChild(line);
    }
    while (view.childElementCount > 400) view.removeChild(view.firstChild);
    if (atBottom) view.scrollTop = view.scrollHeight;
  } catch {
    // Logs are best-effort.
  }
}

// ----------------------------------------------------------------- actions

async function reactivate() {
  show("activating-view");
  $("progress-bar").style.width = "0%";
  await api("/api/activate", { method: "POST" });
  followActivation();
}

async function deactivate() {
  if (!confirm("Tear down the bond and restore the previous network configuration?")) return;
  stopPolling();
  await api("/api/deactivate", { method: "POST" });
  startPolling();
}

async function signOut() {
  stopPolling();
  if (state.eventSource) state.eventSource.close();
  await api("/api/signout", { method: "POST" });
  state.csrf = "";
  show("signin-view");
}

// ----------------------------------------------------------------- helpers

function titleCase(value) {
  if (!value) return "";
  return value.charAt(0).toUpperCase() + value.slice(1).replace(/_/g, " ");
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]
  );
}

// -------------------------------------------------------------------- start

document.addEventListener("DOMContentLoaded", () => {
  $("signin-form").addEventListener("submit", signIn);
  $("reactivate").addEventListener("click", reactivate);
  $("deactivate").addEventListener("click", deactivate);
  $("signout").addEventListener("click", signOut);
  bootstrap();
});

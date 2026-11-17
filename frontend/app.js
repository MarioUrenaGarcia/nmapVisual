"use strict";

const state = {
  profiles: [],
  customProfiles: [],
  projects: ["General"],
  currentProject: "General",
  networks: [],
  flags: [],
  loadedTarget: "",
  loadedArgs: "",
  currentScanId: null,
  eventSource: null,
  hosts: new Map(),
  lastSeq: 0,
  running: false,
};

const el = (id) => document.getElementById(id);

const targetInput = el("target");
const profileSelect = el("profile");
const argsInput = el("args");
const startBtn = el("start-btn");
const stopBtn = el("stop-btn");
const commandText = el("command-text");
const profileDesc = el("profile-desc");

// ---------- utilidades ----------

function toast(msg, isError) {
  const t = el("toast");
  t.textContent = msg;
  t.className = "toast" + (isError ? " err" : "");
  t.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { t.hidden = true; }, 3500);
}

async function copyText(text, label) {
  if (!text) { toast("Nada que copiar.", true); return; }
  try {
    await navigator.clipboard.writeText(text);
    toast((label || "Copiado") + ".");
  } catch (e) {
    const ta = document.createElement("textarea");
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand("copy"); toast((label || "Copiado") + "."); }
    catch (e2) { toast("No se pudo copiar.", true); }
    ta.remove();
  }
}

function webUrlFor(host) {
  const open = (n) => (host.ports || []).some((p) => p.state === "open" && p.port === String(n));
  if (open(443)) return "https://" + host.ip;
  if (open(8443)) return "https://" + host.ip + ":8443";
  if (open(80)) return "http://" + host.ip;
  if (open(8080)) return "http://" + host.ip + ":8080";
  if (open(8000)) return "http://" + host.ip + ":8000";
  return null;
}

function escapeHtml(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function fmtTime(iso) {
  if (!iso) return "";
  try {
    const d = new Date(iso);
    return d.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  } catch (e) { return iso; }
}

function renderCommandTokens(tokens) {
  commandText.innerHTML = tokens.map((tok, i) => {
    if (i > 0 && tok.startsWith("-")) {
      const desc = flagInfo(tok);
      if (desc) {
        const safe = escapeHtml(desc);
        return `<span class="cmd-flag" data-desc="${safe}">${escapeHtml(tok)}</span>`;
      }
    }
    return escapeHtml(tok);
  }).join(" ");
}

function buildCommand() {
  const target = targetInput.value.trim();
  const args = argsInput.value.trim();
  const tokens = ["nmap"];
  if (args) tokens.push(...args.split(/\s+/));
  if (target) tokens.push(...target.split(/\s+/));
  renderCommandTokens(tokens);
}

function flagInfo(tok) {
  if (!state.flagMap) return null;
  if (state.flagMap[tok]) return state.flagMap[tok];
  // Coincidencia por prefijo: -PS80,443 corresponde a la bandera -PS.
  let best = null;
  for (const f of state.flagList) {
    if (f.length > 1 && tok.startsWith(f) && (!best || f.length > best.length)) best = f;
  }
  return best ? state.flagMap[best] : null;
}

// ---------- entorno ----------

async function loadEnvironment() {
  try {
    const res = await fetch("/api/environment");
    const env = await res.json();
    state.profiles = env.profiles || [];
    state.customProfiles = env.customProfiles || [];
    state.projects = env.projects && env.projects.length ? env.projects : ["General"];
    state.networks = env.networks || [];
    if (!state.projects.includes(state.currentProject)) state.currentProject = state.projects[0];
    renderProfiles();
    renderProjects();
    renderEnv(env);
    renderNetworkHint();
  } catch (e) {
    el("env-panel").innerHTML = '<div class="env-row">No se pudo conectar con el servidor.</div>';
  }
}

function renderEnv(env) {
  const panel = el("env-panel");
  const rows = [];

  if (env.testMode) {
    rows.push(`<div class="env-row"><span class="env-badge badge-warn">MODO PRUEBA</span></div>`);
    rows.push(`<div class="env-row">Datos simulados. No se lanza nmap ni se toca la red.</div>`);
  }

  if (env.nmapFound) {
    rows.push(`<div class="env-row"><span class="env-badge badge-ok">nmap listo</span></div>`);
    if (env.nmapVersion) rows.push(`<div class="env-row">${escapeHtml(env.nmapVersion)}</div>`);
  } else {
    rows.push(`<div class="env-row"><span class="env-badge badge-err">nmap no encontrado</span></div>`);
    rows.push(`<div class="env-row">Instala nmap desde nmap.org o define la variable NMAP_PATH.</div>`);
  }

  if (env.isAdmin) {
    rows.push(`<div class="env-row"><span class="env-badge badge-ok">administrador</span></div>`);
  } else {
    rows.push(`<div class="env-row"><span class="env-badge badge-warn">sin privilegios de admin</span></div>`);
    rows.push(`<div class="env-row">Las plantillas intensas (SYN, SO, UDP) necesitan admin. Las de conexion TCP funcionan igual.</div>`);
  }

  if (!env.hasNpcap) {
    rows.push(`<div class="env-row"><span class="env-badge badge-warn">Npcap no detectado</span></div>`);
    rows.push(`<div class="env-row">Instala Npcap para el escaneo crudo en Windows.</div>`);
  }

  panel.innerHTML = rows.join("");
}

// ---------- referencia de banderas ----------

async function loadFlags() {
  try {
    const res = await fetch("/api/flags");
    state.flags = await res.json();
    state.flagMap = {};
    state.flagList = [];
    state.flags.forEach((g) => g.items.forEach((it) => {
      state.flagMap[it.flag] = it.desc;
      state.flagList.push(it.flag);
    }));
    buildCommand();
  } catch (e) { /* ignora */ }
}

// Tooltip flotante para las banderas del comando.
const cmdTip = document.createElement("div");
cmdTip.className = "cmd-tip";
cmdTip.hidden = true;
document.body.appendChild(cmdTip);

commandText.addEventListener("mouseover", (e) => {
  const f = e.target.closest(".cmd-flag");
  if (!f) return;
  cmdTip.textContent = f.dataset.desc;
  cmdTip.hidden = false;
  const r = f.getBoundingClientRect();
  let left = r.left;
  left = Math.min(left, window.innerWidth - cmdTip.offsetWidth - 12);
  cmdTip.style.left = Math.max(8, left) + "px";
  cmdTip.style.top = (r.bottom + 6) + "px";
});
commandText.addEventListener("mouseout", (e) => {
  if (e.target.closest(".cmd-flag")) cmdTip.hidden = true;
});

function openFlags() {
  renderFlags("");
  el("flags-modal").hidden = false;
  const search = el("flags-search");
  search.value = "";
  search.focus();
}

function closeFlags() {
  el("flags-modal").hidden = true;
}

function renderFlags(filter) {
  const body = el("flags-body");
  const q = (filter || "").trim().toLowerCase();
  body.innerHTML = "";
  let shown = 0;

  state.flags.forEach((group) => {
    const items = group.items.filter((it) =>
      !q || it.flag.toLowerCase().includes(q) || it.desc.toLowerCase().includes(q)
    );
    if (!items.length) return;
    shown += items.length;

    const g = document.createElement("div");
    g.className = "flag-group";
    g.innerHTML = `<p class="flag-group-title">${escapeHtml(group.category)}</p>`;
    items.forEach((it) => {
      const row = document.createElement("div");
      row.className = "flag-row";
      row.innerHTML = `
        <span class="flag-code">${escapeHtml(it.flag)}</span>
        <span class="flag-desc">${escapeHtml(it.desc)}${it.admin ? '<span class="flag-admin">admin</span>' : ""}</span>`;
      row.addEventListener("click", () => insertFlag(it.flag));
      g.appendChild(row);
    });
    body.appendChild(g);
  });

  if (!shown) {
    body.innerHTML = '<p class="empty">Ninguna bandera coincide con la busqueda.</p>';
  }
}

// Anade un script NSE al comando, combinandolo con un --script ya existente.
function addScript(name) {
  const tokens = argsInput.value.trim() ? argsInput.value.trim().split(/\s+/) : [];
  const i = tokens.indexOf("--script");
  if (i !== -1 && tokens[i + 1]) {
    const list = tokens[i + 1].split(",").filter(Boolean);
    if (list.includes(name)) { toast(name + " ya esta en el comando."); return; }
    list.push(name);
    tokens[i + 1] = list.join(",");
  } else {
    tokens.push("--script", name);
  }
  argsInput.value = tokens.join(" ");
  profileDesc.textContent = "Argumentos personalizados.";
  buildCommand();
  toast("Script " + name + " anadido al comando.");
}

// ---------- chuleta de nombres sin DNS ----------

function openHostnames() { el("hostnames-modal").hidden = false; }
function closeHostnames() { el("hostnames-modal").hidden = true; }

el("hostnames-btn").addEventListener("click", openHostnames);
el("hostnames-close").addEventListener("click", closeHostnames);
el("hostnames-modal").addEventListener("click", (e) => { if (e.target === el("hostnames-modal")) closeHostnames(); });
el("hostnames-modal").addEventListener("click", (e) => {
  const btn = e.target.closest(".hn-add");
  if (!btn) return;
  if (btn.dataset.script) addScript(btn.dataset.script);
  else if (btn.dataset.flag) insertFlag(btn.dataset.flag);
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !el("hostnames-modal").hidden) closeHostnames();
});

function insertFlag(flag) {
  const current = argsInput.value.trim();
  const tokens = current ? current.split(/\s+/) : [];
  if (tokens.includes(flag)) {
    toast(flag + " ya esta en el comando.");
    return;
  }
  argsInput.value = (current ? current + " " : "") + flag;
  profileDesc.textContent = "Argumentos personalizados.";
  buildCommand();
  toast(flag + " anadido al comando.");
}

el("flags-btn").addEventListener("click", openFlags);
el("flags-close").addEventListener("click", closeFlags);
el("flags-modal").addEventListener("click", (e) => {
  if (e.target === el("flags-modal")) closeFlags();
});
el("flags-search").addEventListener("input", (e) => renderFlags(e.target.value));
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !el("flags-modal").hidden) closeFlags();
});

// ---------- chuleta de puertos ----------

const RISK_LABEL = { alto: "riesgo alto", medio: "riesgo medio", bajo: "riesgo bajo" };

function renderPorts(filter) {
  const body = el("ports-body");
  const q = (filter || "").trim().toLowerCase();
  const catalog = typeof PORT_CATALOG !== "undefined" ? PORT_CATALOG : [];
  const items = catalog.filter((e) => {
    if (!q) return true;
    const hay = [e.p, e.t, e.s, e.c, e.d, e.v, e.tip, e.nse, RISK_LABEL[e.r]]
      .filter(Boolean).join(" ").toLowerCase();
    return hay.includes(q);
  }).sort((a, b) => a.p - b.p || a.t.localeCompare(b.t));
  if (!items.length) {
    body.innerHTML = '<p class="empty">Ningun puerto coincide con la busqueda.</p>';
    return;
  }
  body.innerHTML = items.map((e) => {
    const nse = e.nse ? `<div class="port-nse"><span class="lbl">Scripts nmap</span> <code>${escapeHtml(e.nse)}</code></div>` : "";
    return `<div class="port-card port-r-${e.r}">
      <div class="port-card-head">
        <button type="button" class="port-card-num" data-port="${e.p}" title="Anadir ${e.p} al comando">${e.p}<span class="port-card-proto">/${escapeHtml(e.t)}</span></button>
        <span class="port-card-svc">${escapeHtml(e.s)}</span>
        <span class="port-card-risk risk-${e.r}">${RISK_LABEL[e.r] || ""}</span>
      </div>
      <p class="port-card-desc">${escapeHtml(e.d)}</p>
      <div class="port-card-row"><span class="lbl">A vigilar</span> ${escapeHtml(e.v)}</div>
      <div class="port-card-row"><span class="lbl">Como asegurarlo</span> ${escapeHtml(e.tip)}</div>
      ${nse}
    </div>`;
  }).join("");
}

// Anade un puerto al comando, combinandolo con un -p ya existente si lo hay.
function addPortToCommand(port) {
  const tokens = argsInput.value.trim() ? argsInput.value.trim().split(/\s+/) : [];
  const i = tokens.indexOf("-p");
  if (i !== -1 && tokens[i + 1]) {
    const list = tokens[i + 1].split(",").filter(Boolean);
    if (list.includes(String(port))) {
      toast("El puerto " + port + " ya esta en el comando.");
      return;
    }
    list.push(String(port));
    tokens[i + 1] = list.join(",");
  } else {
    tokens.push("-p", String(port));
  }
  argsInput.value = tokens.join(" ");
  profileDesc.textContent = "Argumentos personalizados.";
  buildCommand();
  toast("Puerto " + port + " anadido al comando.");
}

function openPorts() {
  renderPorts("");
  el("ports-modal").hidden = false;
  const search = el("ports-search");
  search.value = "";
  search.focus();
}
function closePorts() { el("ports-modal").hidden = true; }

el("ports-btn").addEventListener("click", openPorts);
el("ports-close").addEventListener("click", closePorts);
el("ports-modal").addEventListener("click", (e) => { if (e.target === el("ports-modal")) closePorts(); });
el("ports-search").addEventListener("input", (e) => renderPorts(e.target.value));
el("ports-body").addEventListener("click", (e) => {
  const btn = e.target.closest(".port-card-num");
  if (!btn || !btn.dataset.port) return;
  addPortToCommand(btn.dataset.port);
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !el("ports-modal").hidden) closePorts();
});

// ---------- catalogo de comandos de terminal ----------

const CMD_CAT_LABEL = {
  archivos: "archivos", red: "red", procesos: "procesos", permisos: "permisos",
  sistema: "sistema", paquetes: "paquetes", texto: "texto", disco: "disco",
  usuarios: "usuarios", seguridad: "seguridad",
};
const cmdState = { os: "linux" };

function renderCommands(filter) {
  const body = el("commands-body");
  const q = (filter || "").trim().toLowerCase();
  const catalog = typeof CMD_CATALOG !== "undefined" ? CMD_CATALOG : [];
  const items = catalog.filter((e) => {
    if (e.os !== cmdState.os) return false;
    if (!q) return true;
    const hay = [e.cmd, e.syntax, e.desc, e.cat, CMD_CAT_LABEL[e.cat]]
      .filter(Boolean).join(" ").toLowerCase();
    return hay.includes(q);
  }).sort((a, b) => a.cmd.toLowerCase().localeCompare(b.cmd.toLowerCase()));

  const hint = el("commands-hint");
  const total = catalog.filter((e) => e.os === cmdState.os).length;
  hint.textContent = q
    ? `${items.length} de ${total} comandos coinciden en ${cmdState.os}.`
    : `${total} comandos para ${cmdState.os}. Pulsa el nombre para copiar el ejemplo.`;

  if (!items.length) {
    body.innerHTML = '<p class="empty">Ningun comando coincide con la busqueda.</p>';
    return;
  }
  body.innerHTML = items.map((e) => `<div class="cmd-card cmd-cat-${escapeHtml(e.cat)}">
      <div class="cmd-card-head">
        <button type="button" class="cmd-card-name" data-syntax="${escapeHtml(e.syntax)}" title="Copiar: ${escapeHtml(e.syntax)}">${escapeHtml(e.cmd)}</button>
        <span class="cmd-card-cat">${escapeHtml(CMD_CAT_LABEL[e.cat] || e.cat)}</span>
      </div>
      <code class="cmd-card-syntax">${escapeHtml(e.syntax)}</code>
      <p class="cmd-card-desc">${escapeHtml(e.desc)}</p>
    </div>`).join("");
}

function openCommands() {
  renderCommands("");
  el("commands-modal").hidden = false;
  const search = el("commands-search");
  search.value = "";
  search.focus();
}
function closeCommands() { el("commands-modal").hidden = true; }

el("commands-btn").addEventListener("click", openCommands);
el("commands-close").addEventListener("click", closeCommands);
el("commands-modal").addEventListener("click", (e) => { if (e.target === el("commands-modal")) closeCommands(); });
el("commands-search").addEventListener("input", (e) => renderCommands(e.target.value));
el("os-tabs").addEventListener("click", (e) => {
  const tab = e.target.closest(".os-tab");
  if (!tab || !tab.dataset.os) return;
  cmdState.os = tab.dataset.os;
  document.querySelectorAll("#os-tabs .os-tab").forEach((t) => t.classList.toggle("active", t === tab));
  renderCommands(el("commands-search").value);
});
el("commands-body").addEventListener("click", (e) => {
  const btn = e.target.closest(".cmd-card-name");
  if (!btn || !btn.dataset.syntax) return;
  copyText(btn.dataset.syntax, "Ejemplo copiado");
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !el("commands-modal").hidden) closeCommands();
});

function renderNetworkHint() {
  const hint = el("net-hint");
  const btn = el("scan-network-btn");
  if (state.networks.length) {
    hint.textContent = "Red detectada: " + state.networks.map((n) => n.cidr).join("  ");
    btn.disabled = false;
  } else {
    hint.textContent = "No se detecto una red local. Escribe el rango a mano.";
  }
}

el("scan-network-btn").addEventListener("click", () => {
  if (!state.networks.length) {
    toast("No se detecto una red local. Escribe el objetivo a mano (ej. 192.168.1.0/24).", true);
    return;
  }
  const cidr = state.networks[0].cidr;
  targetInput.value = cidr;
  const netProfile = state.profiles.find((p) => p.id === "netmap");
  if (netProfile) {
    profileSelect.value = "netmap";
    applyProfile(netProfile);
  }
  buildCommand();
  startScan();
});

function allProfiles() {
  return [...state.profiles, ...(state.customProfiles || [])];
}

function renderProfiles(selectId) {
  profileSelect.innerHTML = "";
  state.profiles.forEach((p) => {
    const opt = document.createElement("option");
    opt.value = p.id;
    opt.textContent = p.name + (p.requires_admin ? "  (admin)" : "");
    profileSelect.appendChild(opt);
  });
  if (state.customProfiles && state.customProfiles.length) {
    const group = document.createElement("optgroup");
    group.label = "Mis plantillas";
    state.customProfiles.forEach((p) => {
      const opt = document.createElement("option");
      opt.value = p.id;
      opt.textContent = p.name;
      group.appendChild(opt);
    });
    profileSelect.appendChild(group);
  }
  const target = selectId && allProfiles().find((p) => p.id === selectId);
  if (target) {
    profileSelect.value = selectId;
    applyProfile(target);
  } else {
    applyProfile(state.profiles[0]);
  }
}

function applyProfile(p) {
  if (!p) return;
  argsInput.value = p.args;
  profileDesc.textContent = p.description || "";
  el("delete-profile-btn").hidden = !p.custom;
  buildCommand();
}

profileSelect.addEventListener("change", () => {
  const p = allProfiles().find((x) => x.id === profileSelect.value);
  applyProfile(p);
});

el("save-profile-btn").addEventListener("click", async () => {
  const args = argsInput.value.trim();
  const name = (prompt("Nombre para la plantilla:", "") || "").trim();
  if (!name) return;
  try {
    const res = await fetch("/api/profiles/custom", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, args }),
    });
    if (res.status === 404) { toast("Funcion nueva: cierra y vuelve a abrir nmap Visual para actualizar el servidor.", true); return; }
    const data = await res.json();
    if (!res.ok) { toast(data.error || "No se pudo guardar.", true); return; }
    state.customProfiles.push(data);
    renderProfiles(data.id);
    toast(`Plantilla "${name}" guardada.`);
  } catch (e) {
    toast("No se pudo guardar la plantilla.", true);
  }
});

el("delete-profile-btn").addEventListener("click", async () => {
  const id = profileSelect.value;
  const p = (state.customProfiles || []).find((x) => x.id === id);
  if (!p) return;
  if (!confirm(`Borrar la plantilla "${p.name}"?`)) return;
  try {
    await fetch("/api/profiles/custom/delete", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id }),
    });
    state.customProfiles = state.customProfiles.filter((x) => x.id !== id);
    renderProfiles();
    toast("Plantilla borrada.");
  } catch (e) {
    toast("No se pudo borrar.", true);
  }
});

targetInput.addEventListener("input", buildCommand);
argsInput.addEventListener("input", () => {
  profileDesc.textContent = "Argumentos personalizados.";
  buildCommand();
});

// ---------- control del escaneo ----------

startBtn.addEventListener("click", startScan);
stopBtn.addEventListener("click", stopScan);
targetInput.addEventListener("keydown", (e) => { if (e.key === "Enter") startScan(); });
argsInput.addEventListener("keydown", (e) => { if (e.key === "Enter") startScan(); });

async function startScan() {
  const target = targetInput.value.trim();
  const args = argsInput.value.trim();
  if (!target) { toast("Indica un objetivo para escanear.", true); targetInput.focus(); return; }

  startBtn.disabled = true;
  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target, args,
        project: state.currentProject === "__all__" ? "General" : state.currentProject,
        sequential: el("sequential-mode").checked,
      }),
    });
    const data = await res.json();
    if (!res.ok) { toast(data.error || "No se pudo iniciar el escaneo.", true); startBtn.disabled = false; return; }
    resetView();
    openScan(data.id);
    loadHistory();
  } catch (e) {
    toast("Error de conexion al iniciar el escaneo.", true);
    startBtn.disabled = false;
  }
}

async function stopScan() {
  if (!state.currentScanId) return;
  stopBtn.disabled = true;
  try {
    await fetch(`/api/scan/${state.currentScanId}/stop`, { method: "POST" });
    toast("Deteniendo escaneo...");
  } catch (e) {
    toast("No se pudo detener.", true);
  }
}

function resetView() {
  state.hosts.clear();
  state.lastSeq = 0;
  dirtyHosts.clear();
  collapsedHosts.clear();
  pendingLog = [];
  hostFilter.text = "";
  hostFilter.onlyOpen = false;
  hostFilter.onlyRisk = false;
  el("host-search").value = "";
  el("filter-open").classList.remove("on");
  el("filter-risk").classList.remove("on");
  el("host-filter").hidden = true;
  el("hosts").innerHTML = "";
  el("diagnostics").innerHTML = "";
  el("log").innerHTML = "";
  el("host-counter").textContent = "0";
  el("diag-counter").textContent = "0";
  el("hosts-empty").hidden = false;
  el("diag-empty").hidden = false;
  el("downloads").hidden = true;
  el("reuse-config-btn").hidden = true;
  el("use-hosts-btn").hidden = true;
  setProgress(0, "", "");
}

function openScan(scanId) {
  if (state.eventSource) { state.eventSource.close(); state.eventSource = null; }
  state.currentScanId = scanId;
  state.hosts.clear();
  state.lastSeq = 0;
  markHistoryActive(scanId);
  setupDownloads(scanId);

  const es = new EventSource(`/api/scan/${scanId}/stream`);
  state.eventSource = es;
  es.onmessage = (ev) => {
    let data;
    try { data = JSON.parse(ev.data); } catch (e) { return; }
    handleEvent(data);
  };
  es.onerror = () => {
    // El navegador reintenta solo; si el escaneo ya termino se cierra desde handleEvent.
  };
}

// ---------- manejo de eventos ----------

function handleEvent(ev) {
  switch (ev.type) {
    case "snapshot": applySnapshot(ev); break;
    case "status": setStatus(ev.status); break;
    case "progress": setProgress(ev.percent, ev.task, ev.remaining); break;
    case "host": upsertHost(ev.host); break;
    case "diagnostic": addDiagnostic(ev); break;
    case "log": if (ev.seq > state.lastSeq) { state.lastSeq = ev.seq; appendLog(ev.line); } break;
    case "done": finishScan(ev); break;
  }
}

function applySnapshot(snap) {
  state.lastSeq = snap.seq || 0;
  setStatus(snap.status);
  if (snap.progress) setProgress(snap.progress.percent, snap.progress.task, snap.progress.remaining);

  state.hosts.clear();
  el("hosts").innerHTML = "";
  (snap.hosts || []).forEach((h) => upsertHost(h));

  el("diagnostics").innerHTML = "";
  (snap.diagnostics || []).forEach((d) => addDiagnostic(d, true));

  el("log").innerHTML = "";
  (snap.log || []).forEach((entry) => appendLog(entry.line));

  if (snap.command) renderCommandTokens(snap.command.split(/\s+/));
  state.loadedTarget = snap.target || "";
  state.loadedArgs = snap.args || "";
}

function setStatus(status) {
  const chip = el("status-chip");
  const map = {
    running: ["escaneando", "chip-running"],
    done: ["completado", "chip-done"],
    failed: ["con errores", "chip-failed"],
    cancelled: ["cancelado", "chip-cancelled"],
    queued: ["en cola", ""],
  };
  const [label, cls] = map[status] || ["en espera", ""];
  chip.textContent = label;
  chip.className = "status-chip " + cls;

  state.running = status === "running";
  startBtn.disabled = state.running;
  stopBtn.disabled = !state.running;
}

function setProgress(percent, task, remaining) {
  percent = Math.max(0, Math.min(100, percent || 0));
  el("progress-fill").style.width = percent + "%";
  const txt = task ? `${task}  ${percent.toFixed(1)}%` : (percent > 0 ? `${percent.toFixed(1)}%` : "Sin actividad");
  el("progress-text").textContent = txt;
  el("progress-eta").textContent = remaining ? `quedan ${remaining}` : "";
}

// ---------- hosts ----------
// Los eventos pueden llegar a rafagas (una red /24 genera cientos). Para que la
// interfaz nunca se congele, actualizamos el estado al instante pero agrupamos los
// redibujados del DOM en un unico paso por frame con requestAnimationFrame.

const dirtyHosts = new Set();
const collapsedHosts = new Set();
let pendingLog = [];
let renderScheduled = false;

function scheduleRender() {
  if (renderScheduled) return;
  renderScheduled = true;
  requestAnimationFrame(flushRender);
  // Respaldo: requestAnimationFrame se pausa con la pestana en segundo plano.
  // Un temporizador garantiza que los resultados se dibujen igualmente.
  setTimeout(() => { if (renderScheduled) flushRender(); }, 250);
}

function flushRender() {
  renderScheduled = false;

  if (pendingLog.length) {
    const logEl = el("log");
    const atBottom = logEl.scrollTop + logEl.clientHeight >= logEl.scrollHeight - 40;
    const frag = document.createDocumentFragment();
    for (const line of pendingLog) frag.appendChild(makeLogSpan(line));
    pendingLog = [];
    logEl.appendChild(frag);
    while (logEl.childNodes.length > 2000) logEl.removeChild(logEl.firstChild);
    if (atBottom) logEl.scrollTop = logEl.scrollHeight;
  }

  if (dirtyHosts.size) {
    el("hosts-empty").hidden = true;
    const container = el("hosts");
    const frag = document.createDocumentFragment();
    let appended = false;
    for (const ip of dirtyHosts) {
      const host = state.hosts.get(ip);
      if (!host) continue;
      const card = renderHostCard(host);
      const old = document.getElementById("host-" + cssId(ip));
      if (old) {
        old.replaceWith(card);
      } else {
        frag.appendChild(card);
        appended = true;
      }
    }
    if (appended) container.appendChild(frag);
    dirtyHosts.clear();
    if (state.hosts.size > 0) {
      el("host-filter").hidden = false;
      el("use-hosts-btn").hidden = false;
    }
    refreshHostView();
  }
}

function upsertHost(host) {
  if (!host || !host.ip) return;
  if (host.status === "down") {
    state.hosts.delete(host.ip);
    const old = document.getElementById("host-" + cssId(host.ip));
    if (old) old.remove();
    el("host-counter").textContent = String(state.hosts.size);
    return;
  }
  const prev = state.hosts.get(host.ip) || {};
  // Conserva datos ricos (puertos con version) frente a actualizaciones parciales.
  const merged = Object.assign({}, prev, host);
  if ((!host.ports || host.ports.length === 0) && prev.ports) merged.ports = prev.ports;
  if (host.ports && prev.ports && host.ports.length < prev.ports.length) merged.ports = prev.ports;
  // Un dato vacio entrante no debe borrar uno conocido.
  ["mac", "vendor", "os", "hostname"].forEach((k) => {
    if (!host[k] && prev[k]) merged[k] = prev[k];
  });
  if ((!host.scripts || !host.scripts.length) && prev.scripts) merged.scripts = prev.scripts;
  state.hosts.set(host.ip, merged);
  dirtyHosts.add(host.ip);
  scheduleRender();
}

function cssId(ip) { return ip.replace(/[^a-zA-Z0-9]/g, "_"); }

// Datos de la chuleta para un puerto concreto, si existe.
function portInfo(port) {
  if (typeof PORT_INDEX === "undefined") return null;
  return PORT_INDEX[parseInt(port, 10)] || null;
}

// ---------- iconos de tecnologia ----------
// Iconos propios por categoria de servicio (no logos de marca).
const TECH_ICONS = {
  web: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3c2.5 2.6 2.5 15.4 0 18M12 3c-2.5 2.6-2.5 15.4 0 18"/></svg>',
  db: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><ellipse cx="12" cy="6" rx="7" ry="3"/><path d="M5 6v12c0 1.7 3.1 3 7 3s7-1.3 7-3V6"/><path d="M5 12c0 1.7 3.1 3 7 3s7-1.3 7-3"/></svg>',
  remote: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 9l3 3-3 3"/><path d="M13 15h4"/></svg>',
  file: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 7a2 2 0 0 1 2-2h3l2 2h9a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>',
  dns: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="5" r="2"/><circle cx="5" cy="19" r="2"/><circle cx="19" cy="19" r="2"/><path d="M12 7v3M11 11l-5 6M13 11l5 6"/></svg>',
  mail: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 7l9 6 9-6"/></svg>',
  net: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12a10 10 0 0 1 14 0"/><path d="M8 15a6 6 0 0 1 8 0"/><circle cx="12" cy="18" r="1.3" fill="currentColor"/></svg>',
  infra: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M19 5l-2 2M7 17l-2 2"/></svg>',
  generic: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="4"/></svg>',
};
const TECH_RULES = [
  [/https?|http-proxy|http-alt|www|nginx|apache|iis|tomcat|jetty|lighttpd/i, "web"],
  [/mysql|mariadb|postgres|mongo|redis|mssql|ms-sql|oracle|memcache|elastic|cassandra|couch|db2/i, "db"],
  [/ssh|telnet|rdp|ms-wbt-server|vnc|x11|rlogin/i, "remote"],
  [/ftp|smb|microsoft-ds|netbios|nfs|afp|tftp/i, "file"],
  [/(^|\b)domain\b|dns/i, "dns"],
  [/smtp|imap|pop3|submission/i, "mail"],
  [/upnp|ssdp|mdns/i, "net"],
  [/snmp|ntp|dhcp|ldap|kerberos|rpc/i, "infra"],
];
function serviceCategory(service, product) {
  const s = ((service || "") + " " + (product || "")).toLowerCase();
  for (const [re, cat] of TECH_RULES) if (re.test(s)) return cat;
  return "generic";
}
function serviceIcon(service, product) {
  const cat = serviceCategory(service, product);
  return `<span class="tech-ico tech-${cat}" title="${escapeHtml(service || "")}">${TECH_ICONS[cat]}</span>`;
}

// ---------- filtro de resultados ----------
const hostFilter = { text: "", sort: "ip", onlyOpen: false, onlyRisk: false };

function hostMatches(host) {
  if (!host) return false;
  if (hostFilter.onlyOpen && !(host.ports || []).some((p) => p.state === "open")) return false;
  if (hostFilter.onlyRisk && !hostRisk(host).risky) return false;
  const t = hostFilter.text.trim().toLowerCase();
  if (!t) return true;
  const hay = [host.ip, host.hostname, host.vendor, host.os]
    .concat((host.ports || []).flatMap((p) => [p.port, p.service, p.product, p.version]))
    .filter(Boolean).join(" ").toLowerCase();
  return hay.includes(t);
}

function openCountOf(host) {
  return (host.ports || []).filter((p) => p.state === "open").length;
}

function applyHostFilter() {
  const cards = document.querySelectorAll("#hosts .host-card");
  let visible = 0;
  cards.forEach((card) => {
    const host = state.hosts.get(card.dataset.ip);
    const show = hostMatches(host);
    card.style.display = show ? "" : "none";
    if (show) visible++;
  });
  const anyFilter = hostFilter.text || hostFilter.onlyOpen || hostFilter.onlyRisk;
  el("host-counter").textContent = anyFilter ? `${visible}/${state.hosts.size}` : String(state.hosts.size);
}

function sortHostCards() {
  const container = el("hosts");
  const cards = [...container.querySelectorAll(".host-card")];
  const key = hostFilter.sort;
  cards.sort((a, b) => {
    const ha = state.hosts.get(a.dataset.ip) || {}, hb = state.hosts.get(b.dataset.ip) || {};
    if (key === "ports") return openCountOf(hb) - openCountOf(ha);
    if (key === "risk") return (hostRisk(hb).risky ? 1 : 0) - (hostRisk(ha).risky ? 1 : 0) || openCountOf(hb) - openCountOf(ha);
    if (key === "vendor") return (ha.vendor || "~").localeCompare(hb.vendor || "~");
    return (ipToInt(ha.ip || "") || 0) - (ipToInt(hb.ip || "") || 0);
  });
  cards.forEach((c) => container.appendChild(c));
}

function refreshHostView() {
  sortHostCards();
  applyHostFilter();
}

el("host-search").addEventListener("input", (e) => { hostFilter.text = e.target.value; applyHostFilter(); });
el("host-sort").addEventListener("change", (e) => { hostFilter.sort = e.target.value; refreshHostView(); });
el("filter-open").addEventListener("click", () => {
  hostFilter.onlyOpen = !hostFilter.onlyOpen;
  el("filter-open").classList.toggle("on", hostFilter.onlyOpen);
  applyHostFilter();
});
el("filter-risk").addEventListener("click", () => {
  hostFilter.onlyRisk = !hostFilter.onlyRisk;
  el("filter-risk").classList.toggle("on", hostFilter.onlyRisk);
  applyHostFilter();
});

function renderHostCard(host) {
  const card = document.createElement("div");
  card.className = "host-card";
  card.id = "host-" + cssId(host.ip);
  card.dataset.ip = host.ip;

  const stateClass = host.status === "up" ? "state-up" : host.status === "down" ? "state-down" : "state-unknown";
  const ports = (host.ports || []).filter((p) => p.state !== "closed");
  const openCount = (host.ports || []).filter((p) => p.state === "open").length;

  const risk = hostRisk(host);
  const tags = [];
  if (risk.risky) tags.push(`<span class="tag tag-risk" title="${escapeHtml(risk.reasons.join(". "))}">revisar</span>`);
  if (openCount > 0) tags.push(`<span class="tag tag-open">${openCount} puerto${openCount === 1 ? "" : "s"} abierto${openCount === 1 ? "" : "s"}</span>`);
  else if (host.status === "up") tags.push(`<span class="tag tag-up">activo</span>`);
  if (host.vendor) tags.push(`<span class="tag tag-vendor">${escapeHtml(host.vendor)}</span>`);
  if (host.os) tags.push(`<span class="tag">SO</span>`);

  let body = "";

  const webUrl = webUrlFor(host);
  const actions = [
    `<button class="host-action" data-act="deep" data-ip="${escapeHtml(host.ip)}" title="Escaneo detallado (1000 puertos top) de este equipo">escaneo a fondo</button>`,
    `<button class="host-action" data-act="deep-all" data-ip="${escapeHtml(host.ip)}" title="Escaneo detallado de TODOS los puertos (mas lento)">todos los puertos</button>`,
    webUrl ? `<button class="host-action act-web" data-act="web" data-ip="${escapeHtml(host.ip)}" data-url="${escapeHtml(webUrl)}" title="Abrir ${escapeHtml(webUrl)}">abrir web</button>` : "",
    `<button class="host-action" data-act="copy-ip" data-ip="${escapeHtml(host.ip)}">copiar IP</button>`,
    host.mac ? `<button class="host-action" data-act="copy-mac" data-ip="${escapeHtml(host.ip)}">copiar MAC</button>` : "",
  ].filter(Boolean).join("");
  body += `<div class="host-actions">${actions}</div>`;

  const ident = [];
  if (host.mac) ident.push(`<span><span class="lbl">MAC</span> ${escapeHtml(host.mac)}</span>`);
  if (host.vendor) ident.push(`<span><span class="lbl">Fabricante</span> <span class="vendor">${escapeHtml(host.vendor)}</span></span>`);
  if (host.hostname) ident.push(`<span><span class="lbl">Nombre</span> ${escapeHtml(host.hostname)}</span>`);
  if (ident.length) body += `<div class="host-ident">${ident.join("")}</div>`;

  if (host.os) body += `<p class="host-os">${escapeHtml(host.os)}</p>`;

  if (ports.length) {
    const rows = ports.map((p) => {
      const stCls = p.state === "open" ? "ps-open" : p.state === "filtered" ? "ps-filtered" : "ps-closed";
      const svc = [p.product, p.version, p.extrainfo].filter(Boolean).join(" ");
      const info = portInfo(p.port);
      const numAttrs = info
        ? ` class="port-num port-known" title="${escapeHtml(info.s + ": " + info.d + " [" + (RISK_LABEL[info.r] || "") + "]")}"`
        : ` class="port-num"`;
      // Etiqueta por puerto: solo marca los abiertos que el catalogo considera
      // dignos de revision, con el motivo en el tooltip.
      let flag = "";
      if (info && p.state === "open" && (info.r === "alto" || info.r === "medio")) {
        const txt = info.r === "alto" ? "revisar" : "vigilar";
        flag = ` <span class="port-flag flag-${info.r}" title="${escapeHtml(info.v)}">${txt}</span>`;
      }
      return `<tr>
        <td${numAttrs}>${escapeHtml(p.port)}/${escapeHtml(p.proto)}${flag}</td>
        <td class="port-state ${stCls}">${escapeHtml(p.state)}</td>
        <td class="port-svc">${p.service ? serviceIcon(p.service, p.product) : ""}${escapeHtml(p.service || "")}</td>
        <td class="port-ver">${escapeHtml(svc)}${p.cpe ? `<div class="port-cpe">${escapeHtml(p.cpe)}</div>` : ""}</td>
      </tr>`;
    }).join("");
    body += `<table class="ports-table">
      <thead><tr><th>Puerto</th><th>Estado</th><th>Servicio</th><th>Version</th></tr></thead>
      <tbody>${rows}</tbody></table>`;
  } else if (host.status === "up") {
    body += `<p class="port-ver">Sin puertos abiertos detectados todavia.</p>`;
  }

  // Scripts NSE: a nivel de host y a nivel de puerto.
  const scriptBlocks = [];
  (host.scripts || []).forEach((s) => {
    scriptBlocks.push({ label: s.id, output: s.output });
  });
  (host.ports || []).forEach((p) => {
    (p.scripts || []).forEach((s) => {
      scriptBlocks.push({ label: `${p.port}/${p.proto} - ${s.id}`, output: s.output });
    });
  });
  if (scriptBlocks.length) {
    const scr = scriptBlocks.map((s) =>
      `<details><summary>${escapeHtml(s.label)}</summary><pre>${escapeHtml(s.output)}</pre></details>`
    ).join("");
    body += `<div class="host-scripts"><div class="scripts-head">Scripts NSE</div>${scr}</div>`;
  }

  card.innerHTML = `
    <div class="host-top">
      <div class="host-id">
        <span class="host-state-dot ${stateClass}"></span>
        <span class="host-ip">${escapeHtml(host.ip)}</span>
        ${host.hostname ? `<span class="host-name">${escapeHtml(host.hostname)}</span>` : ""}
      </div>
      <div class="host-tags">${tags.join("")}</div>
    </div>
    <div class="host-body">${body}</div>`;

  const top = card.querySelector(".host-top");
  const bodyEl = card.querySelector(".host-body");
  if (collapsedHosts.has(host.ip)) bodyEl.style.display = "none";
  top.addEventListener("click", () => {
    const collapsed = bodyEl.style.display !== "none";
    bodyEl.style.display = collapsed ? "none" : "";
    if (collapsed) collapsedHosts.add(host.ip);
    else collapsedHosts.delete(host.ip);
  });

  return card;
}

// ---------- diagnosticos ----------

function addDiagnostic(d, fromSnapshot) {
  el("diag-empty").hidden = true;
  const box = document.createElement("div");
  box.className = "diag diag-" + (d.level || "info");
  let fix = "";
  if (d.fix_args) {
    fix = `<div class="diag-fix"><button data-fix="${escapeHtml(d.fix_args)}">aplicar: ${escapeHtml(d.fix_args)}</button></div>`;
  }
  box.innerHTML = `
    <div class="diag-title">${escapeHtml(d.title)}</div>
    <div class="diag-msg">${escapeHtml(d.message)}</div>
    <div class="diag-sugg">${escapeHtml(d.suggestion)}</div>
    ${fix}`;
  if (d.fix_args) {
    box.querySelector("button").addEventListener("click", () => {
      argsInput.value = d.fix_args;
      profileDesc.textContent = "Argumentos sugeridos por el diagnostico.";
      buildCommand();
      toast("Argumentos aplicados. Pulsa Iniciar para reintentar.");
      argsInput.scrollIntoView({ behavior: "smooth", block: "center" });
    });
  }
  const container = el("diagnostics");
  container.appendChild(box);
  el("diag-counter").textContent = String(container.children.length);
}

// ---------- log ----------

function makeLogSpan(line) {
  const span = document.createElement("span");
  let cls = "";
  if (/Discovered open port/i.test(line)) cls = "l-disc";
  else if (/WARNING|Warning/.test(line)) cls = "l-warn";
  else if (/QUITTING|error|failed|Failed/i.test(line)) cls = "l-err";
  else if (/About [\d.]+% done|Stats:/.test(line)) cls = "l-stat";
  if (cls) span.className = cls;
  span.textContent = line + "\n";
  return span;
}

function appendLog(line) {
  pendingLog.push(line);
  if (pendingLog.length > 3000) pendingLog = pendingLog.slice(-3000);
  scheduleRender();
}

el("clear-log").addEventListener("click", () => { el("log").innerHTML = ""; });

// ---------- fin del escaneo ----------

function finishScan(ev) {
  setStatus(ev.status);
  if (ev.status === "done") setProgress(100, "", "");
  if (ev.summary) toast(ev.summary);
  if (state.eventSource) { state.eventSource.close(); state.eventSource = null; }
  loadHistory();
}

// ---------- descargas ----------

function setupDownloads(scanId) {
  el("downloads").hidden = false;
  el("reuse-config-btn").hidden = false;
  el("dl-xml").href = `/api/scan/${scanId}/file/xml`;
  el("dl-nmap").href = `/api/scan/${scanId}/file/nmap`;
  el("dl-gnmap").href = `/api/scan/${scanId}/file/gnmap`;
}

el("reuse-config-btn").addEventListener("click", () => {
  if (!state.loadedTarget && !state.loadedArgs) { toast("Abre un escaneo del historial primero.", true); return; }
  targetInput.value = state.loadedTarget;
  argsInput.value = state.loadedArgs;
  profileDesc.textContent = "Configuracion cargada de un escaneo anterior.";
  buildCommand();
  toast("Configuracion cargada. Pulsa Iniciar para repetir el escaneo.");
  window.scrollTo({ top: 0, behavior: "smooth" });
  targetInput.scrollIntoView({ behavior: "smooth", block: "center" });
});

el("use-hosts-btn").addEventListener("click", () => {
  const ips = [...state.hosts.values()].filter((h) => h.status === "up").map((h) => h.ip);
  if (!ips.length) { toast("No hay equipos que usar como objetivo.", true); return; }
  targetInput.value = ips.join(" ");
  profileDesc.textContent = `${ips.length} equipo(s) cargados como objetivo.`;
  buildCommand();
  toast(`${ips.length} equipo(s) puestos como objetivo. Elige una plantilla y pulsa Iniciar.`);
  targetInput.scrollIntoView({ behavior: "smooth", block: "center" });
});

el("copy-cmd-btn").addEventListener("click", () => copyText(commandText.textContent, "Comando copiado"));

// Acciones por equipo (delegadas: un solo listener que sobrevive a los redibujos).
el("hosts").addEventListener("click", (e) => {
  const btn = e.target.closest(".host-action");
  if (!btn) return;
  e.stopPropagation();
  const host = state.hosts.get(btn.dataset.ip);
  if (!host) return;
  const act = btn.dataset.act;
  if (act === "deep") {
    targetInput.value = host.ip;
    argsInput.value = "-A -T4";
    profileDesc.textContent = "Escaneo a fondo de un equipo (SO, versiones y scripts).";
    buildCommand();
    toast(`Listo para escanear a fondo ${host.ip}. Pulsa Iniciar.`);
    targetInput.scrollIntoView({ behavior: "smooth", block: "center" });
  } else if (act === "deep-all") {
    targetInput.value = host.ip;
    argsInput.value = "-A -p- -T4";
    profileDesc.textContent = "Escaneo a fondo de TODOS los puertos de un equipo (mas lento).";
    buildCommand();
    toast(`Listo para escanear los 65535 puertos de ${host.ip}. Puede tardar. Pulsa Iniciar.`);
    targetInput.scrollIntoView({ behavior: "smooth", block: "center" });
  } else if (act === "web") {
    window.open(btn.dataset.url, "_blank", "noopener");
  } else if (act === "copy-ip") {
    copyText(host.ip, "IP copiada");
  } else if (act === "copy-mac") {
    copyText(host.mac, "MAC copiada");
  }
});

// ---------- historial ----------

async function loadHistory() {
  try {
    const res = await fetch("/api/scans");
    const scans = await res.json();
    renderHistory(scans);
  } catch (e) { /* ignora */ }
}

function renderHistory(scans) {
  const list = el("history-list");
  list.innerHTML = "";
  if (state.currentProject !== "__all__") {
    scans = scans.filter((s) => (s.project || "General") === state.currentProject);
  }
  if (!scans.length) {
    list.innerHTML = '<li class="env-row" style="padding:10px 12px;color:var(--text-faint)">Aun no hay escaneos en este proyecto.</li>';
    return;
  }
  scans.forEach((s) => {
    const li = document.createElement("li");
    li.className = "history-item" + (s.id === state.currentScanId ? " active" : "");
    li.dataset.id = s.id;
    const dotCls = "dot-" + (s.status || "done");
    const current = s.project || "General";
    const opts = state.projects
      .map((p) => `<option value="${escapeHtml(p)}"${p === current ? " selected" : ""}>${escapeHtml(p)}</option>`)
      .join("");
    li.innerHTML = `
      <div class="hi-target">${escapeHtml(s.target || "(sin objetivo)")}</div>
      <div class="hi-meta">
        <span class="hi-dot ${dotCls}"></span>
        <span>${escapeHtml(String(s.hostsUp || 0))} up</span>
        <span>${escapeHtml(String(s.openPorts || 0))} abiertos</span>
        <span>${fmtTime(s.startTime)}</span>
      </div>
      <label class="hi-move" title="Mover este escaneo a otro proyecto">
        <span>Proyecto</span>
        <select class="hi-project">${opts}</select>
      </label>`;
    li.addEventListener("click", () => { resetView(); openScan(s.id); });
    const sel = li.querySelector(".hi-project");
    // El selector vive dentro del elemento clicable: hay que frenar la propagacion
    // para que elegir proyecto no abra el escaneo.
    sel.addEventListener("click", (e) => e.stopPropagation());
    sel.addEventListener("change", (e) => { e.stopPropagation(); moveScanToProject(s.id, sel.value); });
    list.appendChild(li);
  });
}

async function moveScanToProject(scanId, project) {
  try {
    const res = await fetch(`/api/scan/${scanId}/project`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ project }),
    });
    if (res.status === 404) { toast("Funcion nueva: cierra y vuelve a abrir nmap Visual para actualizar el servidor.", true); return; }
    const data = await res.json();
    if (!res.ok) { toast(data.error || "No se pudo mover.", true); return; }
    toast(`Escaneo movido a "${project}".`);
    loadHistory();
  } catch (e) {
    toast("No se pudo mover el escaneo.", true);
  }
}

function markHistoryActive(scanId) {
  document.querySelectorAll(".history-item").forEach((li) => {
    li.classList.toggle("active", li.dataset.id === scanId);
  });
}

el("refresh-history").addEventListener("click", loadHistory);

el("clear-history").addEventListener("click", async () => {
  if (!confirm("Borrar todo el historial de escaneos? Esto elimina tambien sus archivos guardados.")) return;
  try {
    const res = await fetch("/api/scans/clear", { method: "POST" });
    const data = await res.json();
    toast(`Historial borrado (${data.removed || 0}).`);
  } catch (e) {
    toast("No se pudo borrar el historial.", true);
    return;
  }
  if (state.eventSource) { state.eventSource.close(); state.eventSource = null; }
  state.currentScanId = null;
  resetView();
  loadHistory();
});

el("quit-btn").addEventListener("click", async () => {
  if (state.running && !confirm("Hay un escaneo en curso. Apagar el servidor de todas formas?")) return;
  try { await fetch("/api/quit", { method: "POST" }); } catch (e) { /* el servidor se cierra */ }
  document.body.innerHTML =
    '<div style="display:flex;height:100vh;align-items:center;justify-content:center;' +
    'color:#8b98a8;font-family:system-ui;font-size:15px;text-align:center;padding:24px">' +
    'Servidor apagado. Puedes cerrar esta pestana.<br>Para volver a abrirlo, usa el acceso directo nmap Visual.</div>';
});

// ---------- evaluacion de riesgo ----------
// Marca dispositivos que conviene revisar: servicios sensibles expuestos,
// demasiados puertos abiertos o equipos sin identificar que ofrecen servicios.

const RISKY_PORTS = {
  21: "FTP sin cifrar",
  23: "Telnet sin cifrar",
  2323: "Telnet alternativo",
  512: "rexec",
  513: "rlogin",
  514: "rsh",
  3389: "Escritorio remoto (RDP) expuesto",
  5900: "VNC expuesto",
  5901: "VNC expuesto",
  3306: "Base de datos MySQL expuesta",
  5432: "Base de datos PostgreSQL expuesta",
  1433: "Base de datos SQL Server expuesta",
  27017: "Base de datos MongoDB expuesta",
  6379: "Redis expuesto",
  9200: "Elasticsearch expuesto",
  11211: "Memcached expuesto",
  2375: "API de Docker expuesta",
};

function hostRisk(host) {
  const reasons = [];
  const open = (host.ports || []).filter((p) => p.state === "open");
  open.forEach((p) => {
    const lbl = RISKY_PORTS[parseInt(p.port, 10)];
    if (lbl) reasons.push(`Puerto ${p.port}: ${lbl}`);
  });
  if (open.length >= 10) reasons.push(`Muchos puertos abiertos (${open.length})`);
  if (!host.vendor && open.length > 0) reasons.push("Fabricante sin identificar que ofrece servicios");
  // Hallazgos de scripts NSE de vulnerabilidad.
  const allScripts = [...(host.scripts || [])];
  open.forEach((p) => (p.scripts || []).forEach((s) => allScripts.push(s)));
  allScripts.forEach((s) => {
    if (/VULNERABLE/i.test(s.output || "")) reasons.push(`Script ${s.id}: posible vulnerabilidad`);
  });
  return { risky: reasons.length > 0, reasons };
}

// ---------- grafo de la red ----------

const SVGNS = "http://www.w3.org/2000/svg";

function svgEl(name, attrs) {
  const e = document.createElementNS(SVGNS, name);
  for (const k in attrs) e.setAttribute(k, attrs[k]);
  return e;
}

function openGraph() {
  renderGraph();
  el("graph-modal").hidden = false;
}
function closeGraph() { el("graph-modal").hidden = true; }

function renderGraph() {
  const wrap = el("graph-wrap");
  wrap.innerHTML = "";
  const hosts = [...state.hosts.values()].filter((h) => h.status === "up");
  if (!hosts.length) {
    wrap.innerHTML = '<div class="graph-empty">No hay dispositivos que mostrar todavia. Haz un escaneo de red primero.</div>';
    return;
  }

  const W = 820;
  const n = hosts.length;
  const ringR = Math.max(150, Math.min(320, 70 + n * 12));
  const H = Math.round(ringR * 2 + 140);
  const cx = W / 2, cy = H / 2;

  const svg = svgEl("svg", { viewBox: `0 0 ${W} ${H}`, xmlns: SVGNS });

  // aristas hub -> host
  const pts = hosts.map((h, i) => {
    const a = (i / n) * Math.PI * 2 - Math.PI / 2;
    return { h, x: cx + Math.cos(a) * ringR, y: cy + Math.sin(a) * ringR };
  });
  pts.forEach((p) => {
    svg.appendChild(svgEl("line", { x1: cx, y1: cy, x2: p.x, y2: p.y, class: "graph-edge" }));
  });

  // hub central
  const hub = svgEl("g", { class: "graph-node" });
  hub.appendChild(svgEl("circle", { cx, cy, r: 26, fill: "var(--accent-2)", stroke: "var(--accent)", "stroke-width": 1.5 }));
  const hubLabel = svgEl("text", { x: cx, y: cy + 4, "text-anchor": "middle", class: "graph-label", fill: "#fff" });
  hubLabel.textContent = "Red";
  hub.appendChild(hubLabel);
  svg.appendChild(hub);

  // nodos de hosts
  pts.forEach((p) => {
    const h = p.h;
    const open = (h.ports || []).filter((x) => x.state === "open");
    const risk = hostRisk(h);
    const r = 10 + Math.min(open.length * 2, 16);
    const color = risk.risky ? "var(--red)" : (open.length ? "var(--green)" : "var(--cyan)");
    const g = svgEl("g", { class: "graph-node" });
    const title = svgEl("title");
    const svcs = open.slice(0, 8).map((x) => x.port + "/" + x.proto + (x.service ? " " + x.service : "")).join("\n");
    title.textContent = h.ip + (h.vendor ? "  (" + h.vendor + ")" : "") +
      (h.hostname ? "\n" + h.hostname : "") +
      (open.length ? "\nPuertos:\n" + svcs : "\nSin puertos abiertos") +
      (risk.risky ? "\n\nREVISAR:\n" + risk.reasons.join("\n") : "");
    g.appendChild(title);
    g.appendChild(svgEl("circle", { cx: p.x, cy: p.y, r, fill: color, "fill-opacity": 0.22, stroke: color, "stroke-width": 1.5 }));
    const lblY = p.y > cy ? p.y + r + 14 : p.y - r - 6;
    const t1 = svgEl("text", { x: p.x, y: lblY, "text-anchor": "middle", class: "graph-label" });
    t1.textContent = h.ip;
    g.appendChild(t1);
    if (h.vendor || open.length) {
      const t2 = svgEl("text", { x: p.x, y: lblY + 13, "text-anchor": "middle", class: "graph-label", fill: "var(--text-faint)" });
      t2.textContent = h.vendor ? h.vendor.slice(0, 16) : open.length + " puertos";
      g.appendChild(t2);
    }
    svg.appendChild(g);
  });

  wrap.appendChild(svg);
}

el("graph-btn").addEventListener("click", openGraph);
el("graph-close").addEventListener("click", closeGraph);
el("graph-modal").addEventListener("click", (e) => { if (e.target === el("graph-modal")) closeGraph(); });

// ---------- calculadora de subred ----------

function ipToInt(ip) {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let v = 0;
  for (const p of parts) {
    if (!/^\d+$/.test(p)) return null;
    const n = parseInt(p, 10);
    if (n < 0 || n > 255) return null;
    v = v * 256 + n;
  }
  return v >>> 0;
}
function intToIp(v) {
  return [(v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255].join(".");
}

function calcSubnet(input) {
  const txt = (input || "").trim();
  const m = txt.match(/^(\d+\.\d+\.\d+\.\d+)(?:\/(\d+))?$/);
  if (!m) return { error: "Escribe una IP con prefijo, por ejemplo 192.168.1.0/24." };
  const ipInt = ipToInt(m[1]);
  if (ipInt === null) return { error: "La direccion IP no es valida." };
  const prefix = m[2] === undefined ? 24 : parseInt(m[2], 10);
  if (prefix < 0 || prefix > 32) return { error: "El prefijo debe estar entre 0 y 32." };

  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const network = (ipInt & mask) >>> 0;
  const broadcast = (network | (~mask >>> 0)) >>> 0;
  const total = Math.pow(2, 32 - prefix);

  let firstHost, lastHost, usable;
  if (prefix >= 31) {
    firstHost = network;
    lastHost = broadcast;
    usable = prefix === 32 ? 1 : 2;
  } else {
    firstHost = (network + 1) >>> 0;
    lastHost = (broadcast - 1) >>> 0;
    usable = total - 2;
  }
  const o1 = (ipInt >>> 24) & 255;
  let cls = "Sin clase";
  if (o1 < 128) cls = "A"; else if (o1 < 192) cls = "B"; else if (o1 < 224) cls = "C"; else if (o1 < 240) cls = "D (multicast)"; else cls = "E (reservado)";
  const priv = (o1 === 10) || (o1 === 172 && ((ipInt >>> 16) & 255) >= 16 && ((ipInt >>> 16) & 255) <= 31) || (o1 === 192 && ((ipInt >>> 16) & 255) === 168);

  return {
    rows: [
      ["Direccion", m[1] + "/" + prefix],
      ["Direccion de red", intToIp(network)],
      ["Mascara", intToIp(mask)],
      ["Comodin (wildcard)", intToIp((~mask) >>> 0)],
      ["Broadcast", intToIp(broadcast)],
      ["Primer host util", prefix >= 31 ? intToIp(firstHost) : intToIp(firstHost)],
      ["Ultimo host util", intToIp(lastHost)],
      ["Hosts utilizables", usable.toLocaleString("es")],
      ["Total de direcciones", total.toLocaleString("es")],
      ["Clase", cls + (priv ? "  (rango privado)" : "")],
    ],
  };
}

function renderSubnet() {
  const res = calcSubnet(el("subnet-cidr").value);
  const errEl = el("subnet-err");
  const table = el("subnet-result");
  if (res.error) {
    errEl.textContent = res.error;
    errEl.hidden = false;
    table.hidden = true;
    return;
  }
  errEl.hidden = true;
  table.querySelector("tbody").innerHTML = res.rows
    .map((r) => `<tr><td>${escapeHtml(r[0])}</td><td>${escapeHtml(r[1])}</td></tr>`)
    .join("");
  table.hidden = false;
}

el("subnet-btn").addEventListener("click", () => {
  el("subnet-modal").hidden = false;
  const inp = el("subnet-cidr");
  if (!inp.value && state.networks && state.networks.length) inp.value = state.networks[0].cidr;
  inp.focus();
  if (inp.value) renderSubnet();
});
el("subnet-close").addEventListener("click", () => { el("subnet-modal").hidden = true; });
el("subnet-modal").addEventListener("click", (e) => { if (e.target === el("subnet-modal")) el("subnet-modal").hidden = true; });
el("subnet-calc").addEventListener("click", renderSubnet);
el("subnet-cidr").addEventListener("keydown", (e) => { if (e.key === "Enter") renderSubnet(); });

document.addEventListener("keydown", (e) => {
  if (e.key !== "Escape") return;
  ["graph-modal", "subnet-modal", "compare-modal"].forEach((id) => { if (!el(id).hidden) el(id).hidden = true; });
});

// ---------- comparar escaneos ----------

async function openCompare() {
  let scans = [];
  try { scans = await fetch("/api/scans").then((r) => r.json()); } catch (e) { scans = []; }
  const selA = el("compare-a"), selB = el("compare-b");
  const opts = scans.map((s) =>
    `<option value="${s.id}">${escapeHtml(s.target || "(sin objetivo)")} - ${escapeHtml(fmtTime(s.startTime))}</option>`
  ).join("");
  selA.innerHTML = opts;
  selB.innerHTML = opts;
  if (scans.length >= 2) { selB.value = scans[0].id; selA.value = scans[1].id; }
  el("compare-body").innerHTML = '<p class="graph-empty">Elige dos escaneos y pulsa Comparar.</p>';
  el("compare-modal").hidden = false;
  if (scans.length >= 2) runCompare();
}

async function fetchHosts(id) {
  try {
    const snap = await fetch("/api/scan/" + id).then((r) => r.json());
    const map = new Map();
    (snap.hosts || []).forEach((h) => { if (h.status === "up") map.set(h.ip, h); });
    return { map, target: snap.target };
  } catch (e) { return { map: new Map(), target: "" }; }
}

function openPortSet(host) {
  return new Set((host.ports || []).filter((p) => p.state === "open").map((p) => p.port + "/" + p.proto));
}

function fieldDiffs(a, b) {
  const diffs = [];
  [["hostname", "Nombre"], ["vendor", "Fabricante"], ["os", "Sistema operativo"], ["mac", "MAC"]].forEach(([k, label]) => {
    const va = (a[k] || "").trim(), vb = (b[k] || "").trim();
    if (va !== vb && (va || vb)) diffs.push({ label, before: va || "(vacio)", after: vb || "(vacio)" });
  });
  return diffs;
}

function svcString(p) {
  return [p.service, p.product, p.version, p.extrainfo, p.cpe].filter(Boolean).join(" ");
}

function scriptMap(host) {
  const m = new Map();
  (host.scripts || []).forEach((s) => m.set(s.id, s.output || ""));
  (host.ports || []).forEach((p) => (p.scripts || []).forEach((s) => m.set(`${p.port}/${p.proto} ${s.id}`, s.output || "")));
  return m;
}

function shorten(txt, n) {
  txt = (txt || "").replace(/\s+/g, " ").trim();
  return txt.length > n ? txt.slice(0, n) + "..." : txt;
}

function scriptDiffs(a, b) {
  const ma = scriptMap(a), mb = scriptMap(b), diffs = [];
  new Set([...ma.keys(), ...mb.keys()]).forEach((k) => {
    const va = (ma.get(k) || "").trim(), vb = (mb.get(k) || "").trim();
    if (va !== vb) diffs.push({ label: k, before: shorten(va, 50) || "(ninguno)", after: shorten(vb, 50) || "(ninguno)" });
  });
  return diffs;
}

function serviceDiffs(a, b) {
  const open = (h) => new Map((h.ports || []).filter((p) => p.state === "open").map((p) => [p.port + "/" + p.proto, p]));
  const ma = open(a), mb = open(b);
  const diffs = [];
  ma.forEach((pa, key) => {
    const pb = mb.get(key);
    if (!pb) return;
    const sa = svcString(pa), sb = svcString(pb);
    if (sa !== sb && (sa || sb)) diffs.push({ port: key, before: shorten(sa, 50) || "(desconocido)", after: shorten(sb, 50) || "(desconocido)" });
  });
  return diffs;
}

async function runCompare() {
  const idA = el("compare-a").value, idB = el("compare-b").value;
  if (!idA || !idB) return;
  const body = el("compare-body");
  body.innerHTML = '<p class="graph-empty">Comparando...</p>';
  const [A, B] = await Promise.all([fetchHosts(idA), fetchHosts(idB)]);

  const added = [], removed = [], changed = [];
  B.map.forEach((h, ip) => { if (!A.map.has(ip)) added.push(h); });
  A.map.forEach((h, ip) => { if (!B.map.has(ip)) removed.push(h); });
  A.map.forEach((ha, ip) => {
    const hb = B.map.get(ip);
    if (!hb) return;
    const pa = openPortSet(ha), pb = openPortSet(hb);
    const opened = [...pb].filter((p) => !pa.has(p));
    const closed = [...pa].filter((p) => !pb.has(p));
    const fields = fieldDiffs(ha, hb);
    const svc = serviceDiffs(ha, hb);
    const scripts = scriptDiffs(ha, hb);
    if (opened.length || closed.length || fields.length || svc.length || scripts.length) {
      changed.push({ ip, host: hb, opened, closed, fields, svc, scripts });
    }
  });

  if (idA === idB) {
    body.innerHTML = '<p class="cmp-none">Son el mismo escaneo. Elige dos distintos.</p>';
    return;
  }

  const nameLine = (h) => [h.hostname, h.vendor].filter(Boolean).join("  ");
  let html = `
    <div class="cmp-summary">
      <div class="cmp-stat add"><b>${added.length}</b> equipos nuevos</div>
      <div class="cmp-stat rem"><b>${removed.length}</b> equipos que desaparecieron</div>
      <div class="cmp-stat"><b>${changed.length}</b> equipos con cambios</div>
    </div>`;

  html += `<div class="cmp-section"><h3>Equipos nuevos</h3>`;
  html += added.length ? added.map((h) =>
    `<div class="cmp-row"><span class="cmp-ip add">+ ${escapeHtml(h.ip)}</span><span class="cmp-meta">${escapeHtml(nameLine(h))}</span></div>`
  ).join("") : '<p class="cmp-none">Ninguno.</p>';
  html += `</div>`;

  html += `<div class="cmp-section"><h3>Equipos que desaparecieron</h3>`;
  html += removed.length ? removed.map((h) =>
    `<div class="cmp-row"><span class="cmp-ip rem">- ${escapeHtml(h.ip)}</span><span class="cmp-meta">${escapeHtml(nameLine(h))}</span></div>`
  ).join("") : '<p class="cmp-none">Ninguno.</p>';
  html += `</div>`;

  html += `<div class="cmp-section"><h3>Cambios en equipos</h3>`;
  html += changed.length ? changed.map((c) => {
    const ports = c.opened.map((p) => `<span class="cmp-port opened">+${escapeHtml(p)}</span>`).join("") +
      c.closed.map((p) => `<span class="cmp-port closed">-${escapeHtml(p)}</span>`).join("");
    const fieldLines = c.fields.map((f) =>
      `<div class="cmp-change">${escapeHtml(f.label)}: <span class="was">${escapeHtml(f.before)}</span> a <span class="now">${escapeHtml(f.after)}</span></div>`
    ).join("");
    const svcLines = c.svc.map((s) =>
      `<div class="cmp-change">${escapeHtml(s.port)} servicio: <span class="was">${escapeHtml(s.before)}</span> a <span class="now">${escapeHtml(s.after)}</span></div>`
    ).join("");
    const scriptLines = (c.scripts || []).map((s) =>
      `<div class="cmp-change">Script ${escapeHtml(s.label)}: <span class="was">${escapeHtml(s.before)}</span> a <span class="now">${escapeHtml(s.after)}</span></div>`
    ).join("");
    return `<div class="cmp-row cmp-row-block">
      <span class="cmp-ip">${escapeHtml(c.ip)}</span>
      <div class="cmp-changes">
        ${ports ? `<div class="cmp-ports">${ports}</div>` : ""}
        ${fieldLines}${svcLines}${scriptLines}
      </div>
    </div>`;
  }).join("") : '<p class="cmp-none">Sin cambios en los equipos comunes.</p>';
  html += `</div>`;

  body.innerHTML = html;
}

el("compare-btn").addEventListener("click", openCompare);
el("compare-close").addEventListener("click", () => { el("compare-modal").hidden = true; });
el("compare-modal").addEventListener("click", (e) => { if (e.target === el("compare-modal")) el("compare-modal").hidden = true; });
el("compare-run").addEventListener("click", runCompare);

// ---------- proyectos ----------

function renderProjects() {
  const sel = el("project-select");
  sel.innerHTML = '<option value="__all__">Todos los proyectos</option>' +
    state.projects.map((p) => `<option value="${escapeHtml(p)}">${escapeHtml(p)}</option>`).join("");
  sel.value = state.currentProject;
}

el("project-select").addEventListener("change", (e) => {
  state.currentProject = e.target.value;
  loadHistory();
});

el("new-project-btn").addEventListener("click", async () => {
  const name = (prompt("Nombre del nuevo proyecto:", "") || "").trim();
  if (!name) return;
  try {
    const res = await fetch("/api/projects", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name }),
    });
    if (res.status === 404) { toast("Funcion nueva: cierra y vuelve a abrir nmap Visual para actualizar el servidor.", true); return; }
    const data = await res.json();
    if (!res.ok) { toast(data.error || "No se pudo crear.", true); return; }
    state.projects = data.projects;
    state.currentProject = name;
    renderProjects();
    loadHistory();
    toast(`Proyecto "${name}" creado. Los nuevos escaneos se guardan aqui.`);
  } catch (e) { toast("No se pudo crear el proyecto.", true); }
});

el("del-project-btn").addEventListener("click", async () => {
  const name = state.currentProject;
  if (name === "__all__" || name === "General") {
    toast("Elige un proyecto propio. No se pueden borrar General ni Todos.", true);
    return;
  }
  if (!confirm(`Borrar el proyecto "${name}"? Los escaneos no se borran, solo dejan de agruparse aqui.`)) return;
  try {
    const res = await fetch("/api/projects/delete", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name }),
    });
    const data = await res.json();
    state.projects = data.projects;
    state.currentProject = "General";
    renderProjects();
    loadHistory();
    toast("Proyecto borrado.");
  } catch (e) { toast("No se pudo borrar.", true); }
});

// ---------- arranque ----------

loadEnvironment();
loadHistory();
loadFlags();
buildCommand();

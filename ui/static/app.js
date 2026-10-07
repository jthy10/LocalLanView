// LocalLanView dashboard. No framework, no build step, no inline scripts.
// Everything that comes from the network (device names, banners...) is set
// with textContent, never innerHTML.

const state = {
  csrf: null,
  user: null,
  generatedPassword: false,
  status: null,
  devices: [],
  view: localStorage.getItem("llv.view") || "cards",
  filter: { q: "", type: "", seen: "", trust: "" },
  sort: { key: "lastSeen", asc: false },
  stream: null,
};

const ICONS = {
  "Router": "router", "Access Point": "wifi", "Switch": "switch", "Printer": "printer", "NAS": "nas",
  "Windows PC": "computer", "Mac": "laptop", "Laptop / Computer": "laptop", "Phone": "phone",
  "Tablet": "tablet", "Smart TV": "tv", "Streaming Device": "cast", "Smart Speaker": "speaker",
  "Game Console": "gamepad", "Camera": "camera", "Smart Home Hub": "hub", "IoT Device": "chip",
  "Media Server": "server", "Server": "server", "Raspberry Pi / SBC": "chip", "Virtual Machine": "cube",
  "Wearable": "watch",
};
const TYPES = Object.keys(ICONS).sort();

/* ---------- tiny DOM helpers ---------- */

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "dataset") Object.assign(el.dataset, v);
    else if (v === true) el.setAttribute(k, "");
    else el.setAttribute(k, v);
  }
  append(el, kids);
  return el;
}

function append(el, kids) {
  for (const k of kids.flat(Infinity)) {
    if (k === null || k === undefined || k === false) continue;
    el.append(k instanceof Node ? k : document.createTextNode(String(k)));
  }
}

const SVGNS = "http://www.w3.org/2000/svg";
function icon(name, cls) {
  const svg = document.createElementNS(SVGNS, "svg");
  svg.setAttribute("aria-hidden", "true");
  if (cls) svg.setAttribute("class", cls);
  const use = document.createElementNS(SVGNS, "use");
  use.setAttribute("href", "icons.svg#" + name);
  svg.append(use);
  return svg;
}

const $ = (sel) => document.querySelector(sel);

/* ---------- formatting ---------- */

function ago(iso) {
  if (!iso) return "never";
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 45) return "just now";
  if (s < 3600) return Math.round(s / 60) + " min ago";
  if (s < 86400) return Math.round(s / 3600) + " h ago";
  if (s < 86400 * 30) return Math.round(s / 86400) + " d ago";
  return new Date(iso).toLocaleDateString();
}

function fmtTime(iso) {
  return iso ? new Date(iso).toLocaleString() : "";
}

function deviceType(d) {
  return d.typeOverride || d.type || "Unknown";
}

function label(d) {
  if (d.customName) return d.customName;
  if (d.hostname) return d.hostname;
  if (d.model) return d.model;
  if (d.vendor) return d.vendor + " device";
  if (deviceType(d) !== "Unknown") return deviceType(d);
  if (d.privateMac) return "Device with private MAC";
  return d.ip || d.key;
}

function vendorLabel(d) {
  if (d.vendor) return d.vendor;
  if (d.privateMac) return "Private/randomized address";
  if (d.mac) return "Unknown vendor";
  return "No MAC seen yet";
}

function liveWindowMs() {
  return ((state.status && state.status.liveWindowSeconds) || 600) * 1000;
}

function isOnline(d) {
  return Date.now() - new Date(d.lastSeen).getTime() < liveWindowMs();
}

function ipKey(ip) {
  if (!ip) return [999];
  return ip.split(".").map(Number);
}

/* ---------- API ---------- */

class APIError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

async function api(method, path, body) {
  const opts = { method, headers: {}, credentials: "same-origin" };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  if (method !== "GET" && state.csrf) opts.headers["X-CSRF-Token"] = state.csrf;
  const res = await fetch(path, opts);
  if (res.status === 401 && path !== "/api/login") {
    state.csrf = null;
    showLogin();
    throw new APIError(401, "login required");
  }
  if (res.status === 204) return null;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new APIError(res.status, data.error || res.statusText);
  return data;
}

/* ---------- theme ---------- */

function applyTheme(t) {
  if (t) document.documentElement.dataset.theme = t;
  else delete document.documentElement.dataset.theme;
}
applyTheme(localStorage.getItem("llv.theme"));

function toggleTheme() {
  const cur = document.documentElement.dataset.theme ||
    (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  const next = cur === "dark" ? "light" : "dark";
  localStorage.setItem("llv.theme", next);
  applyTheme(next);
}

/* ---------- toasts ---------- */

function toast(text, kind) {
  const t = h("div", { class: "toast " + (kind || "") }, text);
  $("#toasts").append(t);
  setTimeout(() => t.remove(), 6000);
}

/* ---------- login ---------- */

function showLogin(message) {
  if (state.stream) { state.stream.close(); state.stream = null; }
  $("#topbar").hidden = true;
  $("#banner").hidden = true;
  const err = h("div", { class: "error" }, message || "");
  const user = h("input", { type: "text", id: "user", autocomplete: "username", required: true, value: "admin" });
  const pass = h("input", { type: "password", id: "pass", autocomplete: "current-password", required: true });
  const btn = h("button", { class: "btn btn-primary", type: "submit" }, "Log in");
  const form = h("form", {
    class: "panel login",
    onsubmit: async (e) => {
      e.preventDefault();
      btn.disabled = true;
      err.textContent = "";
      try {
        const r = await api("POST", "/api/login", { user: user.value.trim(), password: pass.value });
        state.csrf = r.csrf;
        state.user = r.user;
        state.generatedPassword = r.generatedPassword;
        start();
      } catch (ex) {
        err.textContent = ex.message;
        pass.value = "";
        pass.focus();
      } finally {
        btn.disabled = false;
      }
    },
  },
    h("div", { class: "brand" }, icon("logo", "logo"), "LocalLanView"),
    h("div", { class: "field" }, h("label", { for: "user" }, "Username"), user),
    h("div", { class: "field" }, h("label", { for: "pass" }, "Password"), pass),
    err,
    btn,
    h("p", { class: "hint" }, "The first-run password was printed in the terminal where LocalLanView started."),
  );
  $("#view").replaceChildren(h("div", { class: "login-wrap" }, form));
  pass.focus();
}

/* ---------- app shell ---------- */

async function start() {
  $("#topbar").hidden = false;
  await Promise.all([loadStatus(), loadDevices()]);
  updateBanner();
  connectStream();
  route();
}

function updateBanner() {
  const b = $("#banner");
  const warnings = [];
  if (state.generatedPassword) {
    warnings.push(h("span", {}, "You're using the generated first-run password. ",
      h("a", { href: "#/settings" }, "Set your own"), "."));
  }
  for (const w of (state.status && state.status.warnings) || []) warnings.push(h("span", {}, w));
  if (!warnings.length) { b.hidden = true; return; }
  b.replaceChildren(icon("warn"), ...warnings.map((w, i) => i ? [" · ", w] : w));
  b.hidden = false;
}

async function loadStatus() {
  state.status = await api("GET", "/api/status");
  renderScanState();
  const badge = $("#alert-badge");
  badge.textContent = state.status.unread;
  badge.hidden = !state.status.unread;
}

async function loadDevices() {
  state.devices = await api("GET", "/api/devices");
}

function renderScanState() {
  const s = state.status && state.status.scan;
  const el = $("#scan-state");
  const btn = $("#scan-btn");
  if (!s) return;
  if (s.running) {
    el.replaceChildren(h("span", { class: "dot on" }), "Scanning…");
    btn.classList.add("spinning");
  } else {
    el.replaceChildren("Last scan " + ago(s.lastEnd));
    btn.classList.remove("spinning");
  }
}

let refreshTimer = null;
function scheduleRefresh() {
  // Coalesce bursts of updates during a scan into one redraw.
  if (refreshTimer) return;
  refreshTimer = setTimeout(async () => {
    refreshTimer = null;
    try {
      await loadDevices();
      const r = currentRoute();
      if (r.name === "devices") renderDevices(true);
    } catch (_) { /* handled by api() */ }
  }, 1500);
}

function connectStream() {
  if (state.stream) state.stream.close();
  const es = new EventSource("/api/stream");
  state.stream = es;
  es.onmessage = (m) => {
    let msg;
    try { msg = JSON.parse(m.data); } catch (_) { return; }
    if (msg.type === "device") scheduleRefresh();
    if (msg.type === "scan") {
      if (state.status) state.status.scan = msg.data;
      renderScanState();
      if (!msg.data.running) { loadStatus(); scheduleRefresh(); }
    }
    if (msg.type === "event") {
      const e = msg.data;
      toast(e.message, e.kind === "new_device" ? "" : "warn");
      if (state.status) {
        state.status.unread = (state.status.unread || 0) + 1;
        const badge = $("#alert-badge");
        badge.textContent = state.status.unread;
        badge.hidden = false;
      }
      if (currentRoute().name === "alerts") renderAlerts();
    }
  };
  es.onerror = () => {
    // EventSource reconnects on its own; if the session expired the next
    // API call will bounce to the login screen.
  };
}

/* ---------- routing ---------- */

function currentRoute() {
  const hash = location.hash.replace(/^#\/?/, "");
  const [name, arg] = hash.split("/");
  if (name === "device" && arg) return { name: "device", id: Number(arg) };
  if (["alerts", "status", "settings"].includes(name)) return { name };
  return { name: "devices" };
}

function route() {
  if (!state.csrf) return;
  const r = currentRoute();
  document.querySelectorAll("[data-nav]").forEach((a) =>
    a.classList.toggle("active", a.dataset.nav === r.name || (r.name === "device" && a.dataset.nav === "devices")));
  window.scrollTo(0, 0);
  if (r.name === "device") renderDevice(r.id);
  else if (r.name === "alerts") renderAlerts();
  else if (r.name === "status") renderStatus();
  else if (r.name === "settings") renderSettings();
  else renderDevices();
}

/* ---------- devices list ---------- */

function filtered() {
  const q = state.filter.q.toLowerCase();
  let ds = state.devices.filter((d) => {
    if (state.filter.type && deviceType(d) !== state.filter.type) return false;
    if (state.filter.seen === "online" && !isOnline(d)) return false;
    if (state.filter.seen === "offline" && isOnline(d)) return false;
    if (state.filter.trust === "trusted" && !d.trusted) return false;
    if (state.filter.trust === "untrusted" && d.trusted) return false;
    if (!q) return true;
    const hay = [label(d), d.hostname, d.ip, d.mac, d.vendor, d.model, deviceType(d), d.notes, ...(d.tags || [])]
      .join(" ").toLowerCase();
    return hay.includes(q);
  });
  const { key, asc } = state.sort;
  const val = (d) => {
    switch (key) {
      case "name": return label(d).toLowerCase();
      case "ip": return ipKey(d.ip);
      case "type": return deviceType(d);
      case "vendor": return vendorLabel(d).toLowerCase();
      case "firstSeen": return d.firstSeen;
      default: return d.lastSeen;
    }
  };
  ds.sort((a, b) => {
    let va = val(a), vb = val(b), c = 0;
    if (Array.isArray(va)) {
      for (let i = 0; i < Math.max(va.length, vb.length) && !c; i++) c = (va[i] || 0) - (vb[i] || 0);
    } else c = va < vb ? -1 : va > vb ? 1 : 0;
    return asc ? c : -c;
  });
  return ds;
}

function typeChip(d) {
  const conf = d.typeOverride ? "high" : d.typeConfidence;
  return h("span", { class: "chip", title: d.typeOverride ? "Set by you" : "Confidence: " + conf },
    deviceType(d), d.typeOverride ? null : h("span", { class: "conf-" + conf }, " ●"));
}

function seenChip(d) {
  return isOnline(d)
    ? h("span", { class: "chip ok" }, h("span", { class: "dot on" }), "Online")
    : h("span", { class: "chip" }, "Seen " + ago(d.lastSeen));
}

function card(d) {
  return h("a", { class: "panel card", href: "#/device/" + d.id },
    h("div", { class: "card-top" },
      h("div", { class: "dev-icon" }, icon(ICONS[deviceType(d)] || "unknown")),
      h("div", { class: "card-title" },
        h("div", { class: "name", title: label(d) }, label(d)),
        h("div", { class: "sub mono" }, d.ip || "—", d.mac ? " · " + d.mac : ""),
      ),
    ),
    h("div", { class: "card-meta" },
      typeChip(d),
      d.trusted ? h("span", { class: "chip accent" }, icon("shield"), "Trusted") : null,
      d.privateMac ? h("span", { class: "chip" }, "Private MAC") : null,
      (d.tags || []).map((t) => h("span", { class: "chip" }, "#" + t)),
    ),
    h("div", { class: "card-foot" },
      h("span", { title: vendorLabel(d) }, truncate(vendorLabel(d), 34)),
      seenChip(d),
    ),
  );
}

function truncate(s, n) {
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}

function deviceTable(ds) {
  const cols = [
    ["name", "Name"], ["ip", "IP"], ["type", "Type"], ["vendor", "Vendor"], [null, "MAC"],
    [null, "Ports"], ["firstSeen", "First seen"], ["lastSeen", "Last seen"],
  ];
  const head = h("tr", {}, cols.map(([k, t]) => h("th", {
    class: k && state.sort.key === k ? "sorted" + (state.sort.asc ? " asc" : "") : null,
    onclick: k ? () => { setSort(k); } : null,
  }, t)));
  const rows = ds.map((d) => h("tr", { onclick: () => { location.hash = "#/device/" + d.id; } },
    h("td", {}, h("div", { class: "name", title: label(d) }, h("span", { class: "dot" + (isOnline(d) ? " on" : "") }), " ", label(d),
      d.trusted ? h("span", { class: "chip accent" }, " Trusted") : null)),
    h("td", { class: "mono" }, d.ip || "—"),
    h("td", {}, typeChip(d)),
    h("td", {}, truncate(vendorLabel(d), 30)),
    h("td", { class: "mono" }, d.mac || "—"),
    h("td", { class: "mono" }, (d.openPorts || []).slice(0, 6).join(", ") + ((d.openPorts || []).length > 6 ? "…" : "")),
    h("td", {}, ago(d.firstSeen)),
    h("td", {}, ago(d.lastSeen)),
  ));
  return h("div", { class: "panel table-wrap" }, h("table", {}, h("thead", {}, head), h("tbody", {}, rows)));
}

function setSort(k) {
  if (state.sort.key === k) state.sort.asc = !state.sort.asc;
  else state.sort = { key: k, asc: k === "name" || k === "ip" || k === "type" || k === "vendor" };
  renderDevices(true);
}

function renderDevices(keepFocus) {
  const view = $("#view");
  const ds = filtered();
  const all = state.devices;
  const online = all.filter(isOnline).length;
  const fresh = all.filter((d) => Date.now() - new Date(d.firstSeen).getTime() < 86400000).length;

  const listArea = h("div", {}, ds.length
    ? (state.view === "table" ? deviceTable(ds) : h("div", { class: "grid" }, ds.map(card)))
    : h("div", { class: "panel empty" }, all.length ? "No devices match these filters." :
      "No devices yet. The first scan runs at startup and takes a minute or two."));

  if (keepFocus && $("#device-list")) {
    $("#device-list").replaceChildren(listArea);
    $("#stat-total").textContent = all.length;
    $("#stat-online").textContent = online;
    $("#stat-new").textContent = fresh;
    return;
  }

  const search = h("input", {
    type: "search", placeholder: "Search name, IP, MAC, vendor, tag…", value: state.filter.q,
    oninput: (e) => { state.filter.q = e.target.value; renderDevices(true); },
  });
  const sel = (key, opts) => h("select", {
    onchange: (e) => { state.filter[key] = e.target.value; renderDevices(true); },
  }, opts.map(([v, t]) => h("option", { value: v, selected: state.filter[key] === v }, t)));

  const types = [...new Set(all.map(deviceType))].sort();
  const sortSel = h("select", {
    onchange: (e) => { const [k, dir] = e.target.value.split(":"); state.sort = { key: k, asc: dir === "asc" }; renderDevices(true); },
  }, [["lastSeen:desc", "Last seen"], ["name:asc", "Name"], ["ip:asc", "IP address"], ["type:asc", "Type"],
    ["vendor:asc", "Vendor"], ["firstSeen:desc", "Newest first"]].map(([v, t]) =>
    h("option", { value: v, selected: v === state.sort.key + ":" + (state.sort.asc ? "asc" : "desc") }, t)));

  const viewBtn = (mode, ic, title) => h("button", {
    type: "button", class: state.view === mode ? "on" : null, title, "aria-label": title,
    onclick: () => { state.view = mode; localStorage.setItem("llv.view", mode); renderDevices(); },
  }, icon(ic));

  const stat = (id, n, l) => h("div", { class: "panel stat" }, h("div", { class: "num", id }, n), h("div", { class: "lbl" }, l));
  const net = state.status && state.status.network;

  view.replaceChildren(
    h("div", { class: "stats" },
      stat("stat-total", all.length, "Devices known"),
      stat("stat-online", online, "Seen recently"),
      stat("stat-new", fresh, "First seen in last 24 h"),
      h("div", { class: "panel stat" },
        h("div", { class: "num mono" }, net ? net.subnet : "—"),
        h("div", { class: "lbl" }, net ? "on " + net.interface + " as " + net.ip : "")),
    ),
    h("div", { class: "toolbar" },
      h("div", { class: "search" }, icon("search"), search),
      sel("type", [["", "All types"], ...types.map((t) => [t, t])]),
      sel("seen", [["", "Any time"], ["online", "Seen recently"], ["offline", "Not seen recently"]]),
      sel("trust", [["", "Trusted & untrusted"], ["trusted", "Trusted only"], ["untrusted", "Untrusted only"]]),
      sortSel,
      h("div", { class: "spacer" }),
      h("div", { class: "seg" }, viewBtn("cards", "grid", "Card view"), viewBtn("table", "list", "Table view")),
    ),
    h("div", { id: "device-list" }, listArea),
  );
}

/* ---------- device detail ---------- */

async function renderDevice(id) {
  const view = $("#view");
  let data;
  try {
    data = await api("GET", "/api/devices/" + id);
  } catch (e) {
    view.replaceChildren(h("a", { class: "back", href: "#/" }, icon("back"), "All devices"),
      h("div", { class: "panel empty" }, e.status === 404 ? "This device no longer exists." : e.message));
    return;
  }
  const d = data.device;

  const save = async (fields, msg) => {
    try {
      await api("PATCH", "/api/devices/" + id, fields);
      if (msg) toast(msg);
      await loadDevices();
      renderDevice(id);
    } catch (e) { toast(e.message, "warn"); }
  };

  const nameInput = h("input", { type: "text", value: d.customName, placeholder: d.hostname || label(d), maxlength: "100" });
  const typeSel = h("select", { onchange: (e) => save({ typeOverride: e.target.value }) },
    h("option", { value: "" }, "Automatic (" + d.type + ")"),
    TYPES.map((t) => h("option", { value: t, selected: d.typeOverride === t }, t)));
  const notes = h("textarea", { placeholder: "Notes about this device…", maxlength: "4000" }, d.notes || "");

  const tagInput = h("input", {
    type: "text", class: "tag-input", placeholder: "Add tag", maxlength: "40",
    onkeydown: (e) => {
      if (e.key === "Enter" && e.target.value.trim()) {
        e.preventDefault();
        save({ tags: [...d.tags, e.target.value.trim()] });
      }
    },
  });

  const kv = (pairs) => h("dl", { class: "kv" }, pairs.filter(Boolean).map(([k, v]) => [h("dt", {}, k), h("dd", {}, v)]));

  const services = data.services.length
    ? h("ul", { class: "list" }, data.services.map((s) => h("li", {},
      h("span", { class: "chip" }, s.source),
      h("div", { class: "grow" },
        h("div", {}, h("strong", {}, s.name || s.type), s.port ? h("span", { class: "mono" }, "  :" + s.port) : null),
        h("div", { class: "banner-text" }, s.type),
        s.info && Object.keys(s.info).length
          ? h("div", { class: "banner-text" }, Object.entries(s.info).slice(0, 8).map(([k, v]) => k + "=" + v).join("  "))
          : null),
      h("span", { class: "time" }, ago(s.lastSeen)))))
    : h("div", { class: "empty" }, "No advertised services seen.");

  const ports = data.ports.length
    ? h("ul", { class: "list" }, data.ports.map((p) => h("li", {},
      h("span", { class: "chip " + (p.open ? "ok" : "") }, p.open ? "open" : "closed"),
      h("div", { class: "grow" },
        h("div", {}, h("strong", { class: "mono" }, p.port + "/tcp"), "  ", p.service || ""),
        p.banner ? h("div", { class: "banner-text" }, p.banner) : null),
      h("span", { class: "time" }, ago(p.lastSeen)))))
    : h("div", { class: "empty" }, (state.status && state.status.features || [])
      .some((f) => f.name === "TCP port scan" && f.active) ? "No open ports found yet." : "Port scanning is turned off.");

  const hist = (items) => items.length
    ? h("ul", { class: "list" }, items.map((x) => h("li", {},
      h("span", { class: "grow mono" }, x.value), x.source ? h("span", { class: "chip" }, x.source) : null,
      h("span", { class: "time", title: "first seen " + fmtTime(x.firstSeen) }, ago(x.lastSeen)))))
    : h("div", { class: "empty" }, "Nothing yet.");

  const events = data.events.length
    ? h("ul", { class: "list" }, data.events.map((e) => h("li", {},
      h("span", { class: "grow" }, e.message), h("span", { class: "time" }, fmtTime(e.time)))))
    : h("div", { class: "empty" }, "No events.");

  const panel = (title, body, extra) => h("section", { class: "panel" },
    h("div", { class: "panel-head" }, h("h2", {}, title), extra || null), body);

  view.replaceChildren(
    h("a", { class: "back", href: "#/" }, icon("back"), "All devices"),
    h("div", { class: "detail-head" },
      h("div", { class: "dev-icon" }, icon(ICONS[deviceType(d)] || "unknown")),
      h("div", { class: "titles" },
        h("h1", {}, label(d)),
        h("div", { class: "sub" }, [d.ip, vendorLabel(d), deviceType(d)].filter(Boolean).join(" · ")),
        h("div", { class: "card-meta" }, seenChip(d), d.trusted ? h("span", { class: "chip accent" }, icon("shield"), "Trusted") : h("span", { class: "chip warn" }, "Not trusted")),
      ),
      h("div", { class: "actions" },
        h("button", { class: "btn", type: "button", onclick: () => save({ trusted: !d.trusted }, d.trusted ? "Unmarked" : "Marked as trusted") },
          icon("shield"), d.trusted ? "Unmark trusted" : "Mark as trusted"),
        h("button", {
          class: "btn btn-danger", type: "button", onclick: async () => {
            if (!confirm("Forget " + label(d) + "? Its history is deleted. If it's still on the network it will show up again as a new device.")) return;
            try {
              await api("DELETE", "/api/devices/" + id);
              await loadDevices();
              location.hash = "#/";
            } catch (e) { toast(e.message, "warn"); }
          },
        }, "Forget"),
      ),
    ),
    h("div", { class: "cols" },
      h("div", { class: "stack" },
        panel("Services", services),
        panel("Ports", ports),
        panel("Events", events),
      ),
      h("div", { class: "stack" },
        panel("Details", h("div", { class: "panel-body" }, kv([
          ["IP address", h("span", { class: "mono" }, d.ip || "—")],
          ["MAC address", h("span", { class: "mono" }, d.mac || "—")],
          ["Vendor", vendorLabel(d) + (d.vendorRegistry ? " (" + d.vendorRegistry + ")" : "")],
          ["Hostname", d.hostname ? d.hostname + " (" + d.hostnameSource + ")" : "—"],
          d.model ? ["Model", d.model] : null,
          ["Type", h("div", {},
            h("span", {}, d.type + " "), h("span", { class: "conf-" + d.typeConfidence }, "(" + d.typeConfidence + " confidence)"),
            d.typeReasons.length ? h("ul", { class: "reasons" }, d.typeReasons.map((r) => h("li", {}, r))) : null)],
          ["First seen", fmtTime(d.firstSeen)],
          ["Last seen", fmtTime(d.lastSeen)],
          ["Found by", (d.sources || []).join(", ")],
          ...Object.entries(d.attrs || {}).map(([k, v]) => [k, v]),
        ]))),
        panel("Your labels", h("div", { class: "panel-body" },
          h("div", { class: "field" }, h("label", {}, "Name"), h("div", { class: "inline" }, nameInput,
            h("button", { class: "btn", type: "button", onclick: () => save({ customName: nameInput.value }, "Saved") }, "Save"))),
          h("div", { class: "field" }, h("label", {}, "Type"), typeSel),
          h("div", { class: "field" }, h("label", {}, "Tags"), h("div", { class: "tags" },
            d.tags.map((t) => h("span", { class: "chip" }, t, h("button", {
              class: "tag-x", type: "button", "aria-label": "Remove tag " + t,
              onclick: () => save({ tags: d.tags.filter((x) => x !== t) }),
            }, icon("x")))), tagInput)),
          h("div", { class: "field" }, h("label", {}, "Notes"), notes,
            h("button", { class: "btn", type: "button", onclick: () => save({ notes: notes.value }, "Notes saved") }, "Save notes")),
        )),
        panel("IP history", hist(data.ipHistory)),
        panel("Hostname history", hist(data.hostnameHistory)),
      ),
    ),
  );
}

/* ---------- alerts ---------- */

const KIND_LABEL = { new_device: "New device", new_port: "New port", ip_mac_changed: "MAC changed", device_back: "Back online" };

async function renderAlerts() {
  const view = $("#view");
  const events = await api("GET", "/api/events?limit=300");
  const markAll = h("button", {
    class: "btn", type: "button", onclick: async () => {
      await api("POST", "/api/events/ack", { id: 0 });
      await loadStatus();
      renderAlerts();
    },
  }, icon("check"), "Mark all as read");

  view.replaceChildren(
    h("section", { class: "panel" },
      h("div", { class: "panel-head" }, h("h1", {}, "Alerts"), events.some((e) => !e.acknowledged) ? markAll : null),
      events.length ? h("ul", { class: "list" }, events.map((e) => h("li", { class: "event" + (e.acknowledged ? "" : " unread") },
        h("span", { class: "chip kind " + (e.kind === "new_device" ? "accent" : "warn") }, KIND_LABEL[e.kind] || e.kind),
        h("span", { class: "grow" }, e.deviceId ? h("a", { href: "#/device/" + e.deviceId }, e.message) : e.message),
        h("span", { class: "time", title: fmtTime(e.time) }, ago(e.time)),
      ))) : h("div", { class: "empty" }, "No alerts yet. New devices and changes show up here."),
    ),
  );
}

/* ---------- status ---------- */

async function renderStatus() {
  await loadStatus();
  const s = state.status;
  const feature = (f) => h("li", { class: "feature " + (f.active ? "on" : "off") },
    h("span", { class: "icon" }, icon(f.active ? "check" : "x")),
    h("div", { class: "grow" }, h("div", {}, f.name), f.reason ? h("div", { class: "why" }, f.reason) : null));
  const kv = (pairs) => h("dl", { class: "kv" }, pairs.map(([k, v]) => [h("dt", {}, k), h("dd", {}, v)]));
  const p = s.privilege;
  $("#view").replaceChildren(
    h("div", { class: "cols" },
      h("div", { class: "stack" },
        h("section", { class: "panel" },
          h("div", { class: "panel-head" }, h("h2", {}, "Discovery features"),
            h("span", { class: "chip " + (p.elevated ? "ok" : "") }, p.elevated ? "Elevated mode" : "Standard mode")),
          h("div", { class: "panel-body" }, h("p", { class: "hint" }, p.reason)),
          h("ul", { class: "list" }, s.features.map(feature)),
        ),
      ),
      h("div", { class: "stack" },
        h("section", { class: "panel" },
          h("div", { class: "panel-head" }, h("h2", {}, "Network")),
          h("div", { class: "panel-body" }, kv([
            ["Interface", s.network.interface],
            ["This machine", h("span", { class: "mono" }, s.network.ip)],
            ["Scanning", h("span", { class: "mono" }, s.network.subnet)],
            ["Scan every", Math.round(s.scan.interval / 60) + " min"],
            ["Last scan", s.scan.lastEnd ? fmtTime(s.scan.lastEnd) : "not finished yet"],
          ])),
        ),
        h("section", { class: "panel" },
          h("div", { class: "panel-head" }, h("h2", {}, "Console")),
          h("div", { class: "panel-body" }, kv([
            ["Listening on", h("span", { class: "mono" }, s.console.addr)],
            ["HTTPS", s.console.tls ? "Yes" : "No"],
            ["Database", h("span", { class: "mono" }, s.dbPath)],
            ["Version", s.version],
          ])),
        ),
      ),
    ),
  );
}

/* ---------- settings ---------- */

function renderSettings() {
  const cur = h("input", { type: "password", autocomplete: "current-password", required: true });
  const nw = h("input", { type: "password", autocomplete: "new-password", required: true, minlength: "12" });
  const nw2 = h("input", { type: "password", autocomplete: "new-password", required: true });
  const err = h("div", { class: "error" });
  const form = h("form", {
    class: "panel-body",
    onsubmit: async (e) => {
      e.preventDefault();
      err.textContent = "";
      if (nw.value !== nw2.value) { err.textContent = "The new passwords don't match."; return; }
      try {
        const r = await api("POST", "/api/password", { current: cur.value, new: nw.value });
        state.csrf = r.csrf;
        state.generatedPassword = false;
        updateBanner();
        form.reset();
        toast("Password changed. Other sessions were logged out.");
      } catch (ex) { err.textContent = ex.message; }
    },
  },
    h("div", { class: "field" }, h("label", {}, "Current password"), cur),
    h("div", { class: "field" }, h("label", {}, "New password"), nw,
      h("div", { class: "hint" }, "At least 12 characters mixing letters, digits and symbols, or 16+ characters of anything.")),
    h("div", { class: "field" }, h("label", {}, "Repeat new password"), nw2),
    err,
    h("button", { class: "btn btn-primary", type: "submit" }, "Change password"),
  );

  $("#view").replaceChildren(
    h("div", { class: "cols" },
      h("section", { class: "panel" }, h("div", { class: "panel-head" }, h("h2", {}, "Console password")), form),
      h("section", { class: "panel" },
        h("div", { class: "panel-head" }, h("h2", {}, "Export")),
        h("div", { class: "panel-body" },
          h("p", { class: "hint" }, "Download the device inventory. Files are generated locally."),
          h("div", { class: "toolbar" },
            h("a", { class: "btn", href: "/api/export?format=csv", download: true }, "CSV"),
            h("a", { class: "btn", href: "/api/export?format=json", download: true }, "JSON")),
        ),
      ),
    ),
  );
}

/* ---------- boot ---------- */

document.addEventListener("DOMContentLoaded", async () => {
  $("#theme-btn").addEventListener("click", toggleTheme);
  $("#scan-btn").addEventListener("click", async () => {
    try {
      await api("POST", "/api/scan");
      toast("Scan started");
    } catch (e) { if (e.status !== 401) toast(e.message, "warn"); }
  });
  $("#logout-btn").addEventListener("click", async () => {
    try { await api("POST", "/api/logout"); } catch (_) { /* ignore */ }
    state.csrf = null;
    showLogin();
  });
  window.addEventListener("hashchange", route);
  setInterval(() => { if (state.csrf) renderScanState(); }, 30000);

  try {
    const s = await api("GET", "/api/session");
    state.csrf = s.csrf;
    state.user = s.user;
    state.generatedPassword = s.generatedPassword;
    start();
  } catch (_) {
    showLogin();
  }
});

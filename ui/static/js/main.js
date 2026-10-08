// LocalLanView console. No framework, no build step, no inline scripts.

import { state, h, icon, $, api, ago, toast, loadDevices, setUnauthorizedHandler } from "./lib.js";
import * as overview from "./views/overview.js";
import * as devices from "./views/devices.js";
import * as device from "./views/device.js";
import * as alerts from "./views/alerts.js";
import * as status from "./views/status.js";
import * as settings from "./views/settings.js";
import { renderLogin } from "./views/login.js";

const ROUTES = { overview, devices, device, alerts, status, settings };

/* ---------- theme ---------- */

function currentTheme() {
  return document.documentElement.dataset.theme ||
    (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
}

function applyTheme(t) {
  if (t) document.documentElement.dataset.theme = t;
  else delete document.documentElement.dataset.theme;
  const btn = $("#theme-btn");
  if (btn) btn.replaceChildren(icon(currentTheme() === "dark" ? "sun" : "moon"));
}

function toggleTheme() {
  const next = currentTheme() === "dark" ? "light" : "dark";
  try { localStorage.setItem("llv.theme", next); } catch (_) { /* private mode */ }
  applyTheme(next);
}

try { applyTheme(localStorage.getItem("llv.theme")); } catch (_) { /* ignore */ }

/* ---------- shell ---------- */

let shell = null;

function navLink(route, ic, text, extra) {
  return h("a", { href: route === "overview" ? "#/" : "#/" + route, dataset: { nav: route } }, icon(ic), h("span", {}, text), extra || null);
}

function buildShell() {
  const count = h("span", { class: "count", id: "alert-count", hidden: true });
  const netcard = h("div", { class: "netcard", id: "netcard" });
  const scanBtn = h("button", { class: "btn btn-primary", id: "scan-btn", type: "button", onclick: startScan },
    icon("refresh"), h("span", { class: "hide-sm" }, "Scan now"));
  const root = h("div", { class: "shell", id: "shell" },
    h("aside", { class: "sidebar", "aria-label": "Sidebar" },
      h("a", { class: "brand", href: "#/" }, icon("logo", "mark"),
        h("div", {}, h("div", { class: "brand-name" }, "LocalLanView"), h("div", { class: "brand-ver", id: "brand-ver" }))),
      h("div", { class: "nav-label" }, "Monitor"),
      h("nav", { class: "nav" },
        navLink("overview", "overview", "Overview"),
        navLink("devices", "devices", "Devices"),
        navLink("alerts", "bell", "Alerts", count)),
      h("div", { class: "nav-label" }, "System"),
      h("nav", { class: "nav" },
        navLink("status", "radar", "Capabilities"),
        navLink("settings", "gear", "Settings")),
      h("div", { class: "side-foot" },
        netcard,
        h("div", { class: "side-actions" },
          h("div", { class: "user" }, h("span", { class: "avatar" }, (state.user || "a").slice(0, 1)),
            h("span", { class: "ellipsis" }, state.user || "admin")),
          h("button", { class: "btn btn-ghost btn-sm icon-btn", id: "theme-btn", type: "button", title: "Toggle theme", "aria-label": "Toggle theme", onclick: toggleTheme }),
          h("button", { class: "btn btn-ghost btn-sm icon-btn", type: "button", title: "Log out", "aria-label": "Log out", onclick: logout }, icon("logout")),
        ),
      ),
    ),
    h("div", { class: "scrim", onclick: () => root.classList.remove("nav-open") }),
    h("div", { class: "main" },
      h("header", { class: "topbar" },
        h("button", { class: "btn btn-ghost icon-btn menu-btn", type: "button", "aria-label": "Menu", onclick: () => root.classList.toggle("nav-open") }, icon("menu")),
        h("div", { class: "crumbs", id: "crumbs" }),
        h("div", { class: "topbar-right" }, h("div", { class: "scanpill", id: "scanpill" }), scanBtn),
      ),
      h("div", { class: "banner", id: "banner", hidden: true }),
      h("main", { class: "view", id: "view" }),
    ),
  );
  $("#root").replaceChildren(root);
  applyTheme(document.documentElement.dataset.theme);
  shell = root;
}

export function setCrumbs(parts) {
  const el = $("#crumbs");
  if (!el) return;
  const kids = [];
  parts.forEach((p, i) => {
    if (i) kids.push(h("span", { class: "sep" }, icon("chevron")));
    kids.push(p.href ? h("a", { href: p.href }, p.text) : h("span", { class: "here" }, p.text));
  });
  el.replaceChildren(...kids);
}

function renderNetcard() {
  const s = state.status;
  if (!s) return;
  $("#brand-ver").textContent = s.version;
  const n = s.network;
  const row = (k, v) => [h("dt", {}, k), h("dd", { title: v }, v || "—")];
  $("#netcard").replaceChildren(
    h("div", { class: "netcard-head" }, icon("network"), "Network",
      h("span", { class: "badge plain mono", title: "Interface" }, n.interface)),
    h("dl", {}, row("Subnet", n.subnet), row("This host", n.ip), row("Gateway", n.gateway)),
  );
}

function renderScanState() {
  const s = state.status && state.status.scan;
  const pill = $("#scanpill");
  const btn = $("#scan-btn");
  if (!s || !pill) return;
  if (s.running) {
    pill.replaceChildren(h("span", { class: "dot up pulse" }), h("strong", {}, "Scanning"),
      h("span", { class: "when" }, "started " + ago(s.lastStart)));
    btn.classList.add("spinning");
    btn.disabled = true;
  } else {
    const next = s.lastEnd ? new Date(s.lastEnd).getTime() + s.interval * 1000 - Date.now() : 0;
    pill.replaceChildren(h("span", { class: "dot up" }), h("strong", {}, "Idle"),
      h("span", { class: "when" }, s.lastEnd
        ? "last scan " + ago(s.lastEnd) + (next > 60000 ? " · next in " + Math.round(next / 60000) + "m" : "")
        : "waiting for first scan"));
    btn.classList.remove("spinning");
    btn.disabled = false;
  }
}

function renderAlertCount() {
  const c = $("#alert-count");
  if (!c || !state.status) return;
  c.textContent = state.status.unread > 99 ? "99+" : state.status.unread;
  c.hidden = !state.status.unread;
}

export function updateBanner() {
  const b = $("#banner");
  if (!b) return;
  const items = [];
  if (state.generatedPassword) {
    items.push(h("span", {}, "You're using the generated first-run password. ", h("a", { href: "#/settings" }, "Set your own"), "."));
  }
  for (const w of (state.status && state.status.warnings) || []) items.push(h("span", {}, w));
  if (!items.length) { b.hidden = true; return; }
  b.replaceChildren(icon("warn"), ...items);
  b.hidden = false;
}

export async function loadStatus() {
  state.status = await api("GET", "/api/status");
  renderNetcard();
  renderScanState();
  renderAlertCount();
  return state.status;
}

export function markRead(n) {
  if (!state.status) return;
  state.status.unread = n;
  renderAlertCount();
}

/* ---------- live updates ---------- */

let refreshTimer = null;
function scheduleRefresh() {
  // Coalesce bursts of updates during a scan into one redraw.
  if (refreshTimer) return;
  refreshTimer = setTimeout(async () => {
    refreshTimer = null;
    try {
      await loadDevices();
      const mod = ROUTES[currentRoute().name];
      if (mod.onDevices) mod.onDevices();
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
      if (!msg.data.running) { loadStatus().catch(() => {}); scheduleRefresh(); }
    }
    if (msg.type === "event") {
      const e = msg.data;
      toast(e.message, e.kind === "new_device" ? "" : "warn");
      if (state.status) markRead((state.status.unread || 0) + 1);
      const mod = ROUTES[currentRoute().name];
      if (mod.onEvent) mod.onEvent(e);
    }
  };
  // EventSource reconnects on its own; an expired session bounces to the
  // login screen on the next API call.
}

/* ---------- routing ---------- */

function currentRoute() {
  const hash = location.hash.replace(/^#\/?/, "");
  const [name, arg] = hash.split("/");
  if (name === "device" && arg) return { name: "device", id: Number(arg) };
  if (ROUTES[name] && name !== "device") return { name };
  return { name: "overview" };
}

function route() {
  if (!state.csrf) return;
  const r = currentRoute();
  const navName = r.name === "device" ? "devices" : r.name;
  document.querySelectorAll("[data-nav]").forEach((a) => a.classList.toggle("active", a.dataset.nav === navName));
  shell.classList.remove("nav-open");
  window.scrollTo(0, 0);
  ROUTES[r.name].render($("#view"), r);
}

/* ---------- session ---------- */

async function startScan() {
  try {
    await api("POST", "/api/scan");
    toast("Scan started");
  } catch (e) { if (e.status !== 401) toast(e.message, "warn"); }
}

async function logout() {
  try { await api("POST", "/api/logout"); } catch (_) { /* ignore */ }
  state.csrf = null;
  showLogin();
}

function showLogin(message) {
  if (state.stream) { state.stream.close(); state.stream = null; }
  shell = null;
  renderLogin($("#root"), message, start);
}

async function start() {
  buildShell();
  await Promise.all([loadStatus(), loadDevices()]);
  updateBanner();
  connectStream();
  route();
}

setUnauthorizedHandler(() => showLogin());

document.addEventListener("DOMContentLoaded", async () => {
  window.addEventListener("hashchange", route);
  setInterval(() => { if (state.csrf) renderScanState(); }, 30000);
  document.addEventListener("keydown", (e) => {
    if (e.key === "/" && !/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName)) {
      const s = $("#device-search");
      if (s) { e.preventDefault(); s.focus(); }
    }
  });
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

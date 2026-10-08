// Shared state, DOM helpers, API client and formatting.
// Anything that comes from the network (names, banners, ...) goes through
// textContent via h(), never innerHTML.

export const state = {
  csrf: null,
  user: null,
  generatedPassword: false,
  status: null,
  devices: [],
  stream: null,
};

export const ICONS = {
  "Router": "router", "Access Point": "wifi", "Switch": "switch", "Printer": "printer", "NAS": "nas",
  "Windows PC": "computer", "Mac": "laptop", "Laptop / Computer": "laptop", "Phone": "phone",
  "Tablet": "tablet", "Smart TV": "tv", "Streaming Device": "cast", "Smart Speaker": "speaker",
  "Game Console": "gamepad", "Camera": "camera", "Smart Home Hub": "hub", "IoT Device": "chip",
  "Media Server": "server", "Server": "server", "Raspberry Pi / SBC": "chip", "Virtual Machine": "cube",
  "Wearable": "watch",
};
export const TYPES = Object.keys(ICONS).sort();

/* ---------- DOM ---------- */

export function h(tag, attrs, ...kids) {
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

export function append(el, kids) {
  for (const k of kids.flat(Infinity)) {
    if (k === null || k === undefined || k === false) continue;
    el.append(k instanceof Node ? k : document.createTextNode(String(k)));
  }
}

const SVGNS = "http://www.w3.org/2000/svg";
export function icon(name, cls) {
  const svg = document.createElementNS(SVGNS, "svg");
  svg.setAttribute("aria-hidden", "true");
  if (cls) svg.setAttribute("class", cls);
  const use = document.createElementNS(SVGNS, "use");
  use.setAttribute("href", "/icons.svg#" + name);
  svg.append(use);
  return svg;
}

export const $ = (sel, root) => (root || document).querySelector(sel);

/* ---------- formatting ---------- */

export function ago(iso) {
  if (!iso) return "never";
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 45) return "just now";
  if (s < 3600) return Math.round(s / 60) + "m ago";
  if (s < 86400) return Math.round(s / 3600) + "h ago";
  if (s < 86400 * 30) return Math.round(s / 86400) + "d ago";
  return new Date(iso).toLocaleDateString();
}

export function fmtTime(iso) {
  return iso ? new Date(iso).toLocaleString([], { dateStyle: "medium", timeStyle: "short" }) : "";
}

export function truncate(s, n) {
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}

export const deviceType = (d) => d.typeOverride || d.type || "Unknown";
export const typeIcon = (d) => ICONS[deviceType(d)] || "unknown";

export function label(d) {
  if (d.customName) return d.customName;
  if (d.hostname) return d.hostname;
  if (d.model) return d.model;
  if (d.vendor) return d.vendor + " device";
  if (deviceType(d) !== "Unknown") return deviceType(d);
  if (d.privateMac) return "Private device";
  return d.ip || d.key;
}

export function vendorLabel(d) {
  if (d.vendor) return d.vendor;
  if (d.privateMac) return "Private/randomized address";
  if (d.mac) return "Unknown vendor";
  return "No MAC seen yet";
}

export function liveWindowMs() {
  return ((state.status && state.status.liveWindowSeconds) || 600) * 1000;
}
export const isOnline = (d) => Date.now() - new Date(d.lastSeen).getTime() < liveWindowMs();
export const isNew = (d) => Date.now() - new Date(d.firstSeen).getTime() < 86400000;

export function ipKey(ip) {
  if (!ip) return [999];
  return ip.split(".").map(Number);
}

export function ipToInt(ip) {
  const p = ip.split(".").map(Number);
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}

export function intToIp(n) {
  return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
}

/* ---------- small components ---------- */

export function confidence(level, title) {
  return h("span", { class: "conf " + (level || "none"), title: title || "Confidence: " + level }, h("i"), h("i"), h("i"));
}

export function typeCell(d) {
  const conf = d.typeOverride ? "high" : d.typeConfidence;
  return h("span", { class: "type" }, icon(typeIcon(d)), deviceType(d),
    confidence(conf, d.typeOverride ? "Set by you" : "Confidence: " + conf));
}

export function seenBadge(d) {
  return isOnline(d)
    ? h("span", { class: "badge up" }, h("span", { class: "dot up" }), "Online")
    : h("span", { class: "badge" }, h("span", { class: "dot" }), "Seen " + ago(d.lastSeen));
}

export function portList(ports, max) {
  ports = ports || [];
  if (!ports.length) return h("span", { class: "faint" }, "—");
  const shown = ports.slice(0, max);
  return h("span", { class: "ports" }, shown.map((p) => h("span", { class: "port" }, p)),
    ports.length > max ? h("span", { class: "port" }, "+" + (ports.length - max)) : null);
}

export function emptyState(ic, title, text) {
  return h("div", { class: "empty" }, icon(ic), h("strong", {}, title), text ? h("span", {}, text) : null);
}

/* ---------- toasts ---------- */

export function toast(text, kind) {
  const t = h("div", { class: "toast " + (kind || "") }, icon(kind === "warn" ? "warn" : "info"), h("span", {}, text));
  $("#toasts").append(t);
  setTimeout(() => t.remove(), 6000);
}

/* ---------- API ---------- */

export class APIError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

let onUnauthorized = () => {};
export function setUnauthorizedHandler(fn) { onUnauthorized = fn; }

export async function api(method, path, body) {
  const opts = { method, headers: {}, credentials: "same-origin" };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  if (method !== "GET" && state.csrf) opts.headers["X-CSRF-Token"] = state.csrf;
  const res = await fetch(path, opts);
  if (res.status === 401 && path !== "/api/login") {
    state.csrf = null;
    onUnauthorized();
    throw new APIError(401, "login required");
  }
  if (res.status === 204) return null;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new APIError(res.status, data.error || res.statusText);
  return data;
}

export async function loadDevices() {
  state.devices = await api("GET", "/api/devices");
  return state.devices;
}

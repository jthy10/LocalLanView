import {
  state, h, icon, api, ago, label, vendorLabel, deviceType, typeIcon, isOnline, isNew,
  ipToInt, intToIp, emptyState,
} from "../lib.js";
import { setCrumbs, loadStatus } from "../main.js";
import { eventRow } from "./alerts.js";

let root = null;
let events = [];

export async function render(view) {
  root = view;
  setCrumbs([{ text: "Overview" }]);
  draw();
  try {
    [events] = await Promise.all([api("GET", "/api/events?limit=8"), loadStatus()]);
  } catch (_) { return; }
  if (root === view) draw();
}

export function onDevices() { if (root && root.isConnected) draw(); }
export async function onEvent() {
  if (!root || !root.isConnected) return;
  events = await api("GET", "/api/events?limit=8").catch(() => events);
  draw();
}

function draw() {
  const all = state.devices;
  const s = state.status || {};
  const net = s.network || {};
  const online = all.filter(isOnline).length;
  const fresh = all.filter(isNew);
  const portCount = all.reduce((n, d) => n + (d.openPorts || []).length, 0);
  const withPorts = all.filter((d) => (d.openPorts || []).length).length;
  const untrusted = all.filter((d) => !d.trusted).length;

  const kpi = (ic, lbl, value, foot, href) => h(href ? "a" : "div", { class: "panel kpi", href },
    h("div", { class: "kpi-label" }, icon(ic), lbl),
    h("div", { class: "kpi-value" }, value),
    h("div", { class: "kpi-foot" }, foot));

  const pct = all.length ? Math.round((online / all.length) * 100) : 0;
  const meter = h("div", { class: "meter", title: pct + "% online" }, h("i"));
  meter.firstChild.style.width = pct + "%";

  root.replaceChildren(
    h("div", { class: "page-head" },
      h("div", {}, h("h1", {}, "Overview"),
        h("div", { class: "sub" }, net.subnet ? ["Monitoring ", h("span", { class: "mono" }, net.subnet), " on ", net.interface] : "")),
    ),
    h("div", { class: "kpis" },
      kpi("devices", "Devices", all.length, untrusted ? untrusted + " not marked trusted" : "All trusted"),
      kpi("pulse", "Online now", [online, h("small", {}, "/ " + all.length)], [meter, h("span", {}, pct + "%")]),
      kpi("plus-circle", "New in 24h", fresh.length, fresh.length ? "Last joined " + ago(newest(fresh).firstSeen) : "No new devices"),
      kpi("bell", "Unread alerts", s.unread || 0, h("a", { href: "#/alerts" }, "View alerts")),
      kpi("plug", "Open ports", portCount, withPorts ? "on " + withPorts + " device" + (withPorts === 1 ? "" : "s") : "None found"),
    ),
    h("div", { class: "ov-grid" },
      h("section", { class: "panel" },
        h("div", { class: "panel-head" }, h("h2", {}, icon("grid"), "Address space"),
          h("div", { class: "right mono" }, mapRange(net))),
        h("div", { class: "panel-body" }, ipMap(net, all)),
        h("div", { class: "panel-foot" }, h("div", { class: "legend" },
          h("span", {}, h("i", { class: "up" }), "Online"),
          h("span", {}, h("i", { class: "off" }), "Seen before"),
          h("span", {}, h("i", { class: "new" }), "New today"),
          h("span", {}, h("i", { class: "self" }), "This host"),
          h("span", {}, h("i", { class: "gw" }), "Gateway"),
          h("span", {}, h("i"), "Free"))),
      ),
      h("section", { class: "panel" },
        h("div", { class: "panel-head" }, h("h2", {}, icon("layers"), "Device types"),
          h("div", { class: "right" }, all.length + " total")),
        h("div", { class: "panel-body" }, typeBars(all)),
      ),
    ),
    h("div", { class: "ov-grid" },
      h("section", { class: "panel" },
        h("div", { class: "panel-head" }, h("h2", {}, icon("pulse"), "Recent activity"),
          h("div", { class: "right" }, h("a", { href: "#/alerts" }, "All alerts"))),
        events.length ? h("ul", { class: "feed" }, events.map(eventRow))
          : emptyState("bell", "No activity yet", "New devices and changes show up here."),
      ),
      h("section", { class: "panel" },
        h("div", { class: "panel-head" }, h("h2", {}, icon("clock"), "Recently joined"),
          h("div", { class: "right" }, h("a", { href: "#/devices" }, "All devices"))),
        recent(all),
      ),
    ),
  );
}

function newest(ds) {
  return ds.reduce((a, b) => (a.firstSeen > b.firstSeen ? a : b));
}

/* ---------- address map ---------- */

// The map shows the scanned subnet, or the /24 around this host when the
// subnet is bigger than that.
function mapBounds(net) {
  if (!net.subnet || !net.ip) return null;
  const [addr, bitsStr] = net.subnet.split("/");
  let bits = Number(bitsStr);
  let base = ipToInt(addr);
  if (bits < 24) { bits = 24; base = ipToInt(net.ip); }
  const size = 2 ** (32 - bits);
  base = (base - (base % size)) >>> 0;
  return { base, size, bits };
}

function mapRange(net) {
  const b = mapBounds(net);
  return b ? intToIp(b.base) + "/" + b.bits : "";
}

let tip = null;
function showTip(e, lines) {
  if (!tip) { tip = h("div", { class: "tip", role: "tooltip" }); document.body.append(tip); }
  tip.replaceChildren(...lines);
  tip.hidden = false;
  const r = e.target.getBoundingClientRect();
  const tw = tip.offsetWidth, th = tip.offsetHeight;
  let x = r.left + r.width / 2 - tw / 2, y = r.top - th - 8;
  if (y < 8) y = r.bottom + 8;
  x = Math.max(8, Math.min(x, innerWidth - tw - 8));
  tip.style.left = x + "px";
  tip.style.top = y + "px";
}
function hideTip() { if (tip) tip.hidden = true; }
window.addEventListener("hashchange", hideTip);

function ipMap(net, all) {
  const b = mapBounds(net);
  if (!b) return emptyState("grid", "No network detected");
  const byIP = new Map(all.filter((d) => d.ip).map((d) => [d.ip, d]));
  const cells = [];
  for (let i = 0; i < b.size; i++) {
    const ip = intToIp(b.base + i);
    const d = byIP.get(ip);
    let cls = "cell";
    const lines = [];
    if (ip === net.ip) {
      cls += " self";
      lines.push(h("div", { class: "t" }, "This host"), row("Address", ip), row("Interface", net.interface));
    } else if (d) {
      const up = isOnline(d);
      cls += " dev" + (isNew(d) ? " new" : up ? " up" : "");
      lines.push(h("div", { class: "t" }, label(d)), row("Address", ip), row("Type", deviceType(d)),
        row("Vendor", vendorLabel(d)), row("Status", up ? "Online" : "Seen " + ago(d.lastSeen)));
    } else if (b.size > 2 && (i === 0 || i === b.size - 1)) {
      cls += " net";
      lines.push(h("div", { class: "t" }, i === 0 ? "Network address" : "Broadcast"), row("Address", ip));
    } else {
      lines.push(row(ip, "free"));
    }
    if (ip === net.gateway) {
      cls += " gw";
      lines.splice(1, 0, row("Role", "Default gateway"));
    }
    const el = h(d ? "a" : "span", {
      class: cls, href: d ? "#/device/" + d.id : null, "aria-label": d ? label(d) + " " + ip : null,
      onmouseenter: (e) => showTip(e, lines), onmouseleave: hideTip, onfocus: (e) => showTip(e, lines), onblur: hideTip,
    });
    cells.push(el);
  }
  return h("div", { class: "ipmap" }, cells);
}

function row(k, v) {
  return h("div", { class: "r" }, h("span", {}, k), h("b", {}, v));
}

/* ---------- type breakdown ---------- */

function typeBars(all) {
  if (!all.length) return emptyState("layers", "No devices yet");
  const counts = new Map();
  for (const d of all) counts.set(deviceType(d), (counts.get(deviceType(d)) || 0) + 1);
  let rows = [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  if (rows.length > 8) {
    const rest = rows.slice(7).reduce((n, r) => n + r[1], 0);
    rows = [...rows.slice(0, 7), ["Other", rest]];
  }
  const max = Math.max(...rows.map((r) => r[1]));
  return h("div", { class: "bars" }, rows.map(([t, n]) => {
    const fill = h("div", { class: "fill" });
    fill.style.width = (n / max) * 100 + "%";
    return h("div", { class: "bar-row", title: t + ": " + n },
      icon(t === "Other" ? "layers" : typeIcon({ type: t })),
      h("div", {}, h("div", { class: "lbl" }, h("span", { class: "ellipsis" }, t)), h("div", { class: "track" }, fill)),
      h("div", { class: "val" }, n));
  }));
}

/* ---------- recent devices ---------- */

function recent(all) {
  if (!all.length) return emptyState("devices", "No devices yet", "The first scan runs at startup.");
  const ds = [...all].sort((a, b) => (a.firstSeen < b.firstSeen ? 1 : -1)).slice(0, 6);
  return h("ul", { class: "mini" }, ds.map((d) => h("li", {},
    h("a", { href: "#/device/" + d.id },
      h("span", { class: "dev-ico" + (isOnline(d) ? " on" : "") }, icon(typeIcon(d))),
      h("div", { class: "grow" },
        h("div", { class: "name ellipsis" }, label(d)),
        h("div", { class: "sub ellipsis" }, h("span", { class: "mono" }, d.ip || "—"), " · ", vendorLabel(d))),
      h("span", { class: "faint nowrap" }, ago(d.firstSeen))))));
}

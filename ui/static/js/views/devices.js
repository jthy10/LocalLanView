import {
  state, h, icon, ago, label, vendorLabel, deviceType, typeIcon, isOnline, isNew, ipKey,
  typeCell, seenBadge, portList, emptyState, truncate,
} from "../lib.js";
import { setCrumbs } from "../main.js";

const pref = (k, def) => { try { return localStorage.getItem(k) || def; } catch (_) { return def; } };
const ui = {
  layout: pref("llv.layout", "table"),
  q: "",
  scope: "all",
  type: "",
  sort: { key: "ip", asc: true },
};

let root = null;

export function render(view) {
  root = view;
  setCrumbs([{ text: "Devices" }]);
  draw();
}

export function onDevices() { if (root && root.isConnected) drawList(); }

const SCOPES = [
  ["all", "All", () => true],
  ["online", "Online", isOnline],
  ["offline", "Offline", (d) => !isOnline(d)],
  ["new", "New", isNew],
  ["untrusted", "Untrusted", (d) => !d.trusted],
];

function filtered() {
  const q = ui.q.toLowerCase();
  const scope = SCOPES.find((s) => s[0] === ui.scope)[2];
  const ds = state.devices.filter((d) => {
    if (!scope(d)) return false;
    if (ui.type && deviceType(d) !== ui.type) return false;
    if (!q) return true;
    const hay = [label(d), d.hostname, d.ip, d.mac, d.vendor, d.model, deviceType(d), d.notes,
      ...(d.tags || []), ...(d.openPorts || []).map(String)].join(" ").toLowerCase();
    return hay.includes(q);
  });
  const { key, asc } = ui.sort;
  const val = (d) => {
    switch (key) {
      case "name": return label(d).toLowerCase();
      case "type": return deviceType(d);
      case "vendor": return vendorLabel(d).toLowerCase();
      case "mac": return d.mac || "~";
      case "ports": return (d.openPorts || []).length;
      case "firstSeen": return d.firstSeen;
      case "lastSeen": return d.lastSeen;
      default: return ipKey(d.ip);
    }
  };
  ds.sort((a, b) => {
    const va = val(a), vb = val(b);
    let c = 0;
    if (Array.isArray(va)) {
      for (let i = 0; i < Math.max(va.length, vb.length) && !c; i++) c = (va[i] || 0) - (vb[i] || 0);
    } else c = va < vb ? -1 : va > vb ? 1 : 0;
    return asc ? c : -c;
  });
  return ds;
}

function draw() {
  const all = state.devices;
  const search = h("input", {
    type: "search", id: "device-search", placeholder: "Filter by name, IP, MAC, vendor, port…", value: ui.q,
    "aria-label": "Filter devices",
    oninput: (e) => { ui.q = e.target.value; drawList(); },
  });
  const types = [...new Set(all.map(deviceType))].sort();
  const typeSel = h("select", { "aria-label": "Device type", onchange: (e) => { ui.type = e.target.value; drawList(); } },
    h("option", { value: "" }, "All types"),
    types.map((t) => h("option", { value: t, selected: ui.type === t }, t)));

  const layoutBtn = (mode, ic, title) => h("button", {
    type: "button", class: ui.layout === mode ? "on" : null, title, "aria-label": title,
    onclick: () => { ui.layout = mode; try { localStorage.setItem("llv.layout", mode); } catch (_) { /* ignore */ } draw(); },
  }, icon(ic));

  root.replaceChildren(
    h("div", { class: "page-head" },
      h("div", {}, h("h1", {}, "Devices"), h("div", { class: "sub", id: "dev-sub" })),
      h("div", { class: "actions" },
        h("a", { class: "btn", href: "/api/export?format=csv", download: true }, icon("download"), "Export CSV")),
    ),
    h("div", { class: "toolbar" },
      h("div", { class: "seg", id: "scopes", role: "tablist" }),
      h("div", { class: "search" }, icon("search"), search, h("kbd", {}, "/")),
      typeSel,
      h("div", { class: "spacer" }),
      h("div", { class: "seg icons" }, layoutBtn("table", "list", "Table"), layoutBtn("tiles", "grid", "Tiles")),
    ),
    h("div", { id: "device-list" }),
  );
  drawList();
}

function drawList() {
  const all = state.devices;
  const ds = filtered();
  const scopes = root.querySelector("#scopes");
  if (!scopes) return;
  scopes.replaceChildren(...SCOPES.map(([k, t, fn]) => h("button", {
    type: "button", role: "tab", class: ui.scope === k ? "on" : null, "aria-selected": ui.scope === k ? "true" : "false",
    onclick: () => { ui.scope = k; drawList(); },
  }, t, h("span", { class: "n" }, all.filter(fn).length))));
  root.querySelector("#dev-sub").textContent = ds.length === all.length
    ? all.length + " devices on this network"
    : ds.length + " of " + all.length + " devices";

  const list = root.querySelector("#device-list");
  if (!ds.length) {
    list.replaceChildren(h("div", { class: "panel" }, all.length
      ? emptyState("search", "No matching devices", "Try a different filter.")
      : emptyState("radar", "No devices yet", "The first scan runs at startup and takes a minute or two.")));
    return;
  }
  list.replaceChildren(ui.layout === "tiles" ? tiles(ds) : table(ds));
}

function setSort(k) {
  if (ui.sort.key === k) ui.sort.asc = !ui.sort.asc;
  else ui.sort = { key: k, asc: !["lastSeen", "firstSeen", "ports"].includes(k) };
  drawList();
}

function table(ds) {
  const cols = [
    ["name", "Device"], ["ip", "IP address"], ["mac", "MAC address", "hide-sm"], ["type", "Type", "hide-sm"],
    ["vendor", "Vendor", "hide-sm"], ["ports", "Open ports", "hide-sm"], ["lastSeen", "Last seen"],
  ];
  const head = h("tr", {}, cols.map(([k, t, cls]) => {
    const on = ui.sort.key === k;
    return h("th", {
      class: "sortable " + (cls || ""), "aria-sort": on ? (ui.sort.asc ? "ascending" : "descending") : null,
      onclick: () => setSort(k),
    }, t, h("span", { class: "arrow" }, on ? (ui.sort.asc ? "↑" : "↓") : ""));
  }));
  const rows = ds.map((d) => h("tr", { onclick: () => { location.hash = "#/device/" + d.id; } },
    h("td", {}, h("div", { class: "cell-name" },
      h("span", { class: "dev-ico" + (isOnline(d) ? " on" : "") }, icon(typeIcon(d))),
      h("div", { class: "t" },
        h("div", { class: "name", title: label(d) },
          h("a", { href: "#/device/" + d.id, class: "plain-link" }, label(d))),
        subline(d) ? h("div", { class: "sub" }, subline(d)) : null))),
    h("td", { class: "mono" }, d.ip || "—"),
    h("td", { class: "hide-sm" }, h("span", { class: "mac-cell mono", title: d.privateMac ? "Locally administered (randomized) address" : null }, d.mac || "—")),
    h("td", { class: "hide-sm" }, typeCell(d)),
    h("td", { class: "hide-sm", title: vendorLabel(d) }, h("span", { class: d.vendor ? "" : "muted" }, truncate(d.vendor ? d.vendor : d.privateMac ? "Private address" : vendorLabel(d), 24))),
    h("td", { class: "hide-sm" }, portList(d.openPorts, 3)),
    h("td", {}, h("span", { class: "seen-cell" }, h("span", { class: "dot" + (isOnline(d) ? " up" : "") }),
      isOnline(d) ? "Online" : ago(d.lastSeen))),
  ));
  return h("div", { class: "panel table-wrap" }, h("table", {}, h("thead", {}, head), h("tbody", {}, rows)));
}

function subline(d) {
  const bits = [];
  if (d.customName && d.hostname) bits.push(d.hostname);
  if (d.trusted) bits.push("Trusted");
  if (isNew(d)) bits.push("New");
  for (const t of (d.tags || []).slice(0, 2)) bits.push("#" + t);
  return bits.join(" · ");
}

function tiles(ds) {
  return h("div", { class: "tiles" }, ds.map((d) => h("a", { class: "panel tile", href: "#/device/" + d.id },
    h("div", { class: "tile-top" },
      h("span", { class: "dev-ico" + (isOnline(d) ? " on" : "") }, icon(typeIcon(d))),
      h("div", { class: "t" },
        h("div", { class: "name", title: label(d) }, label(d)),
        h("div", { class: "sub" }, vendorLabel(d))),
      seenBadge(d)),
    h("dl", {},
      h("dt", {}, "IP"), h("dd", { class: "mono" }, d.ip || "—"),
      h("dt", {}, "MAC"), h("dd", { class: "mono" }, d.mac || "—"),
      h("dt", {}, "Type"), h("dd", {}, typeCell(d))),
    h("div", { class: "tile-foot" },
      d.trusted ? h("span", { class: "badge accent" }, icon("shield"), "Trusted") : null,
      d.privateMac ? h("span", { class: "badge info" }, "Private MAC") : null,
      isNew(d) ? h("span", { class: "badge warn" }, "New") : null,
      (d.tags || []).map((t) => h("span", { class: "badge" }, "#" + t)),
      h("span", { class: "spacer" }),
      portList(d.openPorts, 3)),
  )));
}

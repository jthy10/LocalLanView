import {
  state, h, icon, api, ago, fmtTime, label, vendorLabel, deviceType, typeIcon, isOnline,
  confidence, seenBadge, emptyState, toast, loadDevices, TYPES,
} from "../lib.js";
import { setCrumbs } from "../main.js";

let tab = "overview";
let currentId = null;

export async function render(view, r) {
  if (r.id !== currentId) { tab = "overview"; currentId = r.id; }
  setCrumbs([{ text: "Devices", href: "#/devices" }, { text: "…" }]);
  let data;
  try {
    data = await api("GET", "/api/devices/" + r.id);
  } catch (e) {
    setCrumbs([{ text: "Devices", href: "#/devices" }, { text: "Not found" }]);
    view.replaceChildren(h("div", { class: "panel" },
      emptyState("unknown", e.status === 404 ? "This device no longer exists" : "Couldn't load device", e.status === 404 ? "It may have been forgotten." : e.message)));
    return;
  }
  draw(view, r.id, data);
}

function draw(view, id, data) {
  const d = data.device;
  setCrumbs([{ text: "Devices", href: "#/devices" }, { text: label(d) }]);

  const save = async (fields, msg) => {
    try {
      await api("PATCH", "/api/devices/" + id, fields);
      if (msg) toast(msg);
      await loadDevices();
      draw(view, id, await api("GET", "/api/devices/" + id));
    } catch (e) { toast(e.message, "warn"); }
  };

  const forget = async () => {
    if (!confirm("Forget " + label(d) + "? Its history is deleted. If it's still on the network it will show up again as a new device.")) return;
    try {
      await api("DELETE", "/api/devices/" + id);
      await loadDevices();
      location.hash = "#/devices";
    } catch (e) { toast(e.message, "warn"); }
  };

  const conf = d.typeOverride ? "high" : d.typeConfidence;
  const spec = (k, v, cls) => h("div", { class: "spec" }, h("div", { class: "k" }, k), h("div", { class: "v " + (cls || ""), title: typeof v === "string" ? v : null }, v));

  const TABS = [
    ["overview", "Overview"],
    ["services", "Services", data.services.length],
    ["ports", "Ports", data.ports.filter((p) => p.open).length],
    ["history", "History"],
    ["events", "Events", data.events.length],
  ];
  const body = h("div", {});
  const tabsEl = h("div", { class: "tabs", role: "tablist" });
  const showTab = (k) => {
    tab = k;
    tabsEl.replaceChildren(...TABS.map(([key, t, n]) => h("button", {
      type: "button", role: "tab", class: tab === key ? "on" : null, "aria-selected": tab === key ? "true" : "false",
      onclick: () => showTab(key),
    }, t, n !== undefined ? h("span", { class: "n" }, n) : null)));
    body.replaceChildren(TAB_RENDER[k](d, data, save));
  };

  view.replaceChildren(
    h("div", { class: "dhead" },
      h("span", { class: "dev-ico lg" + (isOnline(d) ? " on" : "") }, icon(typeIcon(d))),
      h("div", { class: "t" },
        h("h1", {}, label(d), seenBadge(d),
          d.trusted ? h("span", { class: "badge accent" }, icon("shield"), "Trusted") : h("span", { class: "badge warn" }, "Untrusted")),
        h("div", { class: "sub" }, [deviceType(d), vendorLabel(d), d.hostname && d.hostname !== label(d) ? d.hostname : null].filter(Boolean).join(" · "))),
      h("div", { class: "actions" },
        h("button", { class: "btn", type: "button", onclick: () => save({ trusted: !d.trusted }, d.trusted ? "Marked as untrusted" : "Marked as trusted") },
          icon(d.trusted ? "shield-off" : "shield"), d.trusted ? "Mark untrusted" : "Mark trusted"),
        h("button", { class: "btn btn-danger", type: "button", onclick: forget }, icon("trash"), "Forget"),
      ),
    ),
    h("div", { class: "specs" },
      spec("IP address", d.ip || "—", "mono"),
      spec("MAC address", d.mac ? [d.mac, d.privateMac ? h("span", { class: "badge info" }, "private") : null] : "—", "mono"),
      spec("Vendor", vendorLabel(d)),
      spec("Type", [deviceType(d), confidence(conf, d.typeOverride ? "Set by you" : "Confidence: " + conf)]),
      spec("First seen", ago(d.firstSeen)),
      spec("Last seen", isOnline(d) ? "Online now" : ago(d.lastSeen)),
    ),
    tabsEl,
    body,
  );
  showTab(TABS.some((t) => t[0] === tab) ? tab : "overview");
}

const panel = (title, ic, body, right) => h("section", { class: "panel" },
  h("div", { class: "panel-head" }, h("h2", {}, ic ? icon(ic) : null, title), right ? h("div", { class: "right" }, right) : null), body);

const kv = (pairs) => h("dl", { class: "kv" }, pairs.filter(Boolean).map(([k, v]) => [h("dt", {}, k), h("dd", {}, v)]));

const TAB_RENDER = {
  overview(d, data, save) {
    const conf = d.typeOverride ? "high" : d.typeConfidence;
    return h("div", { class: "cols" },
      h("div", { class: "stack" },
        panel("Identification", "info", kv([
          ["IP address", h("span", { class: "mono" }, d.ip || "—")],
          ["MAC address", h("span", { class: "mono" }, d.mac || "—")],
          ["Vendor", vendorLabel(d) + (d.vendorRegistry ? " (" + d.vendorRegistry + ")" : "")],
          ["Hostname", d.hostname ? [d.hostname, " ", h("span", { class: "muted" }, "via " + d.hostnameSource)] : "—"],
          d.model ? ["Model", d.model] : null,
          ["Found by", (d.sources || []).length ? h("span", { class: "tags" }, d.sources.map((s) => h("span", { class: "badge" }, s))) : "—"],
          ["First seen", fmtTime(d.firstSeen)],
          ["Last seen", fmtTime(d.lastSeen)],
          ...Object.entries(d.attrs || {}).map(([k, v]) => [k, h("span", { class: "mono" }, v)]),
        ])),
        panel("Fingerprint", "fingerprint", h("div", { class: "panel-body" },
          h("div", { class: "type" }, icon(typeIcon(d)), h("strong", {}, d.type), confidence(d.typeConfidence),
            h("span", { class: "muted" }, d.typeConfidence + " confidence")),
          d.typeReasons.length
            ? h("ul", { class: "reasons" }, d.typeReasons.map((r) => h("li", {}, icon("check"), r)))
            : h("p", { class: "hint" }, "No signals matched a known device type yet."),
          d.typeOverride ? h("p", { class: "hint" }, "You've set this device to " + d.typeOverride + ", which overrides the guess.") : null,
        ), d.typeOverride ? "overridden" : null),
      ),
      h("div", { class: "stack" }, labelsPanel(d, save)),
    );
  },

  services(d, data) {
    if (!data.services.length) return h("div", { class: "panel" }, emptyState("layers", "No advertised services", "Nothing seen over mDNS, SSDP or NetBIOS."));
    return h("div", { class: "panel" }, h("ul", { class: "rows" }, data.services.map((s) => h("li", {},
      h("span", { class: "badge" }, s.source),
      h("div", { class: "grow" },
        h("div", { class: "title" }, s.name || s.type, s.port ? h("span", { class: "port" }, s.port) : null),
        h("div", { class: "muted mono" }, s.type),
        s.info && Object.keys(s.info).length
          ? h("div", { class: "code" }, Object.entries(s.info).slice(0, 12).map(([k, v]) => k + "=" + v).join("\n"))
          : null),
      h("span", { class: "time" }, ago(s.lastSeen))))));
  },

  ports(d, data) {
    if (!data.ports.length) {
      const on = ((state.status && state.status.features) || []).some((f) => f.name === "TCP port scan" && f.active);
      return h("div", { class: "panel" }, emptyState("plug", on ? "No open ports found" : "Port scanning is off",
        on ? "Common ports are checked on each scan." : "Start without -no-port-scan to probe common ports."));
    }
    return h("div", { class: "panel table-wrap" }, h("table", { class: "cap-table" },
      h("thead", {}, h("tr", {}, h("th", {}, "Port"), h("th", {}, "State"), h("th", {}, "Service"), h("th", { class: "hide-sm" }, "Banner"), h("th", { class: "num" }, "Last seen"))),
      h("tbody", {}, data.ports.map((p) => h("tr", {},
        h("td", { class: "mono" }, p.port + "/tcp"),
        h("td", {}, h("span", { class: "badge " + (p.open ? "up" : "") }, p.open ? "open" : "closed")),
        h("td", {}, p.service || h("span", { class: "faint" }, "—")),
        h("td", { class: "wrap hide-sm" }, p.banner ? h("span", { class: "mono" }, p.banner) : h("span", { class: "faint" }, "—")),
        h("td", { class: "num muted" }, ago(p.lastSeen)))))));
  },

  history(d, data) {
    const hist = (items) => items.length
      ? h("ul", { class: "rows" }, items.map((x) => h("li", {},
        h("div", { class: "grow mono" }, x.value),
        x.source ? h("span", { class: "badge" }, x.source) : null,
        h("span", { class: "time", title: "First seen " + fmtTime(x.firstSeen) }, ago(x.lastSeen)))))
      : emptyState("history", "Nothing recorded yet");
    return h("div", { class: "cols even" },
      panel("IP addresses", "network", hist(data.ipHistory)),
      panel("Hostnames", "tag", hist(data.hostnameHistory)));
  },

  events(d, data) {
    if (!data.events.length) return h("div", { class: "panel" }, emptyState("bell", "No events for this device"));
    return h("div", { class: "panel" }, h("ul", { class: "rows" }, data.events.map((e) => h("li", {},
      h("div", { class: "grow" }, e.message),
      h("span", { class: "time" }, fmtTime(e.time))))));
  },
};

function labelsPanel(d, save) {
  const nameInput = h("input", { type: "text", value: d.customName, placeholder: d.hostname || label(d), maxlength: "100", "aria-label": "Name" });
  const typeSel = h("select", { "aria-label": "Type", onchange: (e) => save({ typeOverride: e.target.value }, "Type updated") },
    h("option", { value: "" }, "Automatic (" + d.type + ")"),
    TYPES.map((t) => h("option", { value: t, selected: d.typeOverride === t }, t)));
  const notes = h("textarea", { placeholder: "Where it lives, who owns it…", maxlength: "4000", "aria-label": "Notes" }, d.notes || "");
  const tagInput = h("input", {
    type: "text", class: "tag-input", placeholder: "Add tag…", maxlength: "40", "aria-label": "Add tag",
    onkeydown: (e) => {
      if (e.key === "Enter" && e.target.value.trim()) {
        e.preventDefault();
        save({ tags: [...d.tags, e.target.value.trim()] });
      }
    },
  });
  return panel("Labels", "tag", h("div", { class: "panel-body" },
    h("div", { class: "field" }, h("label", {}, "Name"), h("div", { class: "inline" }, nameInput,
      h("button", { class: "btn", type: "button", onclick: () => save({ customName: nameInput.value }, "Name saved") }, "Save"))),
    h("div", { class: "field" }, h("label", {}, "Type"), typeSel),
    h("div", { class: "field" }, h("label", {}, "Tags"), h("div", { class: "tags" },
      d.tags.map((t) => h("span", { class: "badge" }, t, h("button", {
        class: "tag-x", type: "button", "aria-label": "Remove tag " + t,
        onclick: () => save({ tags: d.tags.filter((x) => x !== t) }),
      }, icon("x")))), tagInput)),
    h("div", { class: "field" }, h("label", {}, "Notes"), notes),
    h("button", { class: "btn", type: "button", onclick: () => save({ notes: notes.value }, "Notes saved") }, "Save notes"),
  ));
}

import { h, icon, api, ago, fmtTime, emptyState } from "../lib.js";
import { setCrumbs, loadStatus } from "../main.js";

export const KINDS = {
  new_device: { label: "New device", icon: "plus-circle", cls: "" },
  new_port: { label: "New port", icon: "plug", cls: "warn" },
  ip_mac_changed: { label: "MAC changed", icon: "swap", cls: "warn" },
  device_back: { label: "Back online", icon: "arrow-up", cls: "up" },
};

export function eventRow(e) {
  const k = KINDS[e.kind] || { label: e.kind, icon: "info", cls: "info" };
  return h("li", { class: e.acknowledged ? null : "unread" },
    h("span", { class: "ev-ico " + k.cls }, icon(k.icon)),
    h("div", { class: "grow" },
      h("div", { class: "msg" }, e.deviceId ? h("a", { href: "#/device/" + e.deviceId }, e.message) : e.message),
      h("div", { class: "meta" }, h("span", {}, k.label), h("span", { title: fmtTime(e.time) }, ago(e.time)))),
  );
}

let root = null;
let filter = "";

export async function render(view) {
  root = view;
  setCrumbs([{ text: "Alerts" }]);
  await draw();
}

export function onEvent() { if (root && root.isConnected) draw(); }

async function draw() {
  let events;
  try { events = await api("GET", "/api/events?limit=300"); } catch (_) { return; }
  const unread = events.filter((e) => !e.acknowledged).length;
  const shown = filter === "unread" ? events.filter((e) => !e.acknowledged)
    : filter ? events.filter((e) => e.kind === filter) : events;

  const markAll = h("button", {
    class: "btn", type: "button", disabled: !unread, onclick: async () => {
      await api("POST", "/api/events/ack", { id: 0 });
      await loadStatus();
      draw();
    },
  }, icon("check"), "Mark all as read");

  const filters = [["", "All", events.length], ["unread", "Unread", unread],
    ...Object.entries(KINDS).map(([k, v]) => [k, v.label, events.filter((e) => e.kind === k).length])];

  root.replaceChildren(
    h("div", { class: "page-head" },
      h("div", {}, h("h1", {}, "Alerts"),
        h("div", { class: "sub" }, unread ? unread + " unread" : "You're all caught up")),
      h("div", { class: "actions" }, markAll),
    ),
    h("div", { class: "toolbar" },
      h("div", { class: "seg", role: "tablist" }, filters.filter((f) => f[2] || !f[0] || f[0] === "unread").map(([k, t, n]) => h("button", {
        type: "button", role: "tab", class: filter === k ? "on" : null, "aria-selected": filter === k ? "true" : "false",
        onclick: () => { filter = k; draw(); },
      }, t, h("span", { class: "n" }, n)))),
    ),
    h("section", { class: "panel" },
      shown.length ? h("ul", { class: "feed" }, shown.map(eventRow))
        : emptyState("bell", events.length ? "Nothing here" : "No alerts yet", events.length ? "No alerts match this filter." : "New devices, new ports and address changes show up here."),
    ),
  );
}

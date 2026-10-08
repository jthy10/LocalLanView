import { state, h, icon, fmtTime } from "../lib.js";
import { setCrumbs, loadStatus } from "../main.js";

// What each collector does, in one line.
const ABOUT = {
  "ARP table": "Reads the OS neighbor cache",
  "ARP sweep": "Sends raw ARP requests to every address",
  "ICMP ping sweep": "Pings every address in the subnet",
  "mDNS / Bonjour": "Browses multicast DNS service announcements",
  "SSDP / UPnP": "Searches for UPnP devices and reads their descriptions",
  "NetBIOS": "Asks Windows hosts for their names and workgroup",
  "LLMNR": "Resolves names over link-local multicast",
  "TCP port scan": "Checks common ports and grabs banners",
};

export async function render(view) {
  setCrumbs([{ text: "Capabilities" }]);
  try { await loadStatus(); } catch (_) { return; }
  const s = state.status;
  const p = s.privilege;
  const active = s.features.filter((f) => f.active).length;

  const kv = (pairs) => h("dl", { class: "kv" }, pairs.map(([k, v]) => [h("dt", {}, k), h("dd", {}, v)]));
  const mono = (v) => h("span", { class: "mono" }, v || "—");

  view.replaceChildren(
    h("div", { class: "page-head" },
      h("div", {}, h("h1", {}, "Capabilities"),
        h("div", { class: "sub" }, active + " of " + s.features.length + " discovery methods active"))),
    h("div", { class: "cols" },
      h("div", { class: "stack" },
        h("section", { class: "panel" },
          h("div", { class: "mode-card" },
            h("span", { class: "ico " + (p.elevated ? "up" : "warn") }, icon(p.elevated ? "shield" : "lock")),
            h("div", { class: "t" },
              h("strong", {}, p.elevated ? "Elevated mode" : "Standard mode"),
              h("span", {}, p.reason)),
            h("span", { class: "badge mono" }, "-mode " + p.requested))),
        h("section", { class: "panel table-wrap" },
          h("table", { class: "cap-table" },
            h("thead", {}, h("tr", {}, h("th", {}, "Method"), h("th", {}, "State"), h("th", { class: "hide-sm" }, "Details"))),
            h("tbody", {}, s.features.map((f) => h("tr", {},
              h("td", {}, h("div", { class: "feat-name" }, icon(f.active ? "check-circle" : "minus-circle"),
                h("div", {}, h("div", {}, f.name), h("div", { class: "muted" }, ABOUT[f.name] || "")))),
              h("td", {}, h("span", { class: "badge " + (f.active ? "up" : "") }, h("span", { class: "dot" + (f.active ? " up" : "") }), f.active ? "Active" : "Off")),
              h("td", { class: "wrap hide-sm" }, f.reason || (f.active ? "Running every scan" : "")))))),
        ),
      ),
      h("div", { class: "stack" },
        h("section", { class: "panel" },
          h("div", { class: "panel-head" }, h("h2", {}, icon("network"), "Network")),
          h("div", { class: "panel-body" }, kv([
            ["Interface", mono(s.network.interface)],
            ["This host", mono(s.network.ip)],
            ["MAC", mono(s.network.mac)],
            ["Subnet", mono(s.network.subnet)],
            ["Gateway", mono(s.network.gateway)],
            ["Scan interval", Math.round(s.scan.interval / 60) + " min"],
            ["Last scan", s.scan.lastEnd ? fmtTime(s.scan.lastEnd) : "Not finished yet"],
          ]))),
        h("section", { class: "panel" },
          h("div", { class: "panel-head" }, h("h2", {}, icon("globe"), "Console")),
          h("div", { class: "panel-body" }, kv([
            ["Listening on", mono(s.console.addr)],
            ["HTTPS", s.console.tls ? h("span", { class: "badge up" }, icon("lock"), "On") : h("span", { class: "badge" }, "Off")],
            ["Exposure", s.console.loopback ? "This machine only" : h("span", { class: "badge warn" }, "Reachable from the LAN")],
            ["Database", mono(s.dbPath)],
            ["Version", mono(s.version)],
          ]))),
      ),
    ),
  );
}

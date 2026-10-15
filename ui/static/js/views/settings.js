import { state, h, icon, api, toast } from "../lib.js";
import { setCrumbs, updateBanner, loadStatus } from "../main.js";

export async function render(view) {
  setCrumbs([{ text: "Settings" }]);
  try { await loadStatus(); } catch (_) { return; }

  const cur = h("input", { type: "password", id: "pw-current", autocomplete: "current-password", required: true });
  const nw = h("input", { type: "password", id: "pw-new", autocomplete: "new-password", required: true, minlength: "12", "aria-describedby": "pw-hint" });
  const nw2 = h("input", { type: "password", id: "pw-confirm", autocomplete: "new-password", required: true });
  const err = h("div", { class: "error", role: "alert" });
  const form = h("form", {
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
        toast("Password changed. Other sessions were signed out.");
        render(view); // LAN access needs a password of your own
      } catch (ex) { err.textContent = ex.message; }
    },
  },
    h("div", { class: "field" }, h("label", { for: "pw-current" }, "Current password"), cur),
    h("div", { class: "field" }, h("label", { for: "pw-new" }, "New password"), nw,
      h("div", { class: "hint", id: "pw-hint" }, "12+ characters mixing letters, digits and symbols, or 16+ of anything.")),
    h("div", { class: "field" }, h("label", { for: "pw-confirm" }, "Confirm new password"), nw2),
    err,
    h("button", { class: "btn btn-primary", type: "submit" }, icon("key"), "Update password"),
  );

  const section = (title, text, body) => h("section", { class: "panel setting" },
    h("div", { class: "about" }, h("h2", {}, title), h("p", {}, text)), h("div", {}, body));

  view.replaceChildren(
    h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Settings"),
      h("div", { class: "sub" }, "Signed in as " + (state.user || "admin")))),
    h("div", { class: "settings" },
      section("Console password", "Changing it signs out every other session. The password is stored as an argon2id hash.", form),
      section("Use on other devices", "Lets phones, tablets and other computers on this network open LocalLanView. Off by default. Turning it on serves the console over HTTPS on every network interface.",
        lanSetting()),
      section("Export inventory", "Download every known device with its addresses, vendor, type and labels. Generated locally.",
        h("div", { class: "inline" },
          h("a", { class: "btn", href: "/api/export?format=csv", download: true }, icon("download"), "CSV"),
          h("a", { class: "btn", href: "/api/export?format=json", download: true }, icon("download"), "JSON"))),
    ),
  );
}

const isLocalPage = () => ["localhost", "127.0.0.1", "[::1]"].includes(location.hostname);

function lanSetting() {
  const c = (state.status && state.status.console) || {};
  const box = h("input", { type: "checkbox", id: "lan-on", checked: !!c.lan, "aria-describedby": "lan-hint" });
  const err = h("div", { class: "error", role: "alert" });
  let hint = "";
  if (c.locked) {
    box.disabled = true;
    hint = c.locked;
  } else if (state.generatedPassword && !c.lan) {
    box.disabled = true;
    hint = "Set your own password above first.";
  }
  box.addEventListener("change", async () => {
    err.textContent = "";
    box.disabled = true;
    const on = box.checked;
    let r;
    try {
      r = await api("POST", "/api/console", { lan: on });
    } catch (ex) {
      err.textContent = ex.message;
      box.checked = !on;
      box.disabled = false;
      return;
    }
    if (!on && !isLocalPage()) {
      // This device loses access, so there's nowhere to send it.
      body.replaceChildren(h("p", {}, "Access from other devices is off. Open ",
        h("span", { class: "mono" }, r.url), " on the computer running LocalLanView."));
      return;
    }
    // The console restarts on its new address; follow it there and sign in again.
    toast("Restarting the console at " + r.url + "…");
    setTimeout(() => { location.href = r.url + "#/settings"; }, 1500);
  });

  const body = h("div", {},
    h("label", { class: "check", for: "lan-on" }, box, "Open LocalLanView to devices on this network"),
    h("div", { class: "hint", id: "lan-hint" }, hint),
    err,
    c.lanUrl ? h("div", { class: "lan-url" },
      icon("phone"),
      h("div", {},
        h("div", {}, "Go to ", h("a", { class: "mono", href: c.lanUrl }, c.lanUrl), " on any device connected to your network."),
        h("div", { class: "hint" }, "Your browser will warn once about the self-signed certificate; that's expected. " +
          "If the page doesn't load, allow TCP port " + new URL(c.lanUrl).port + " through this computer's firewall."))) : null,
  );
  return body;
}

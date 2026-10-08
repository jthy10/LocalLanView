import { state, h, icon, api, toast } from "../lib.js";
import { setCrumbs, updateBanner } from "../main.js";

export function render(view) {
  setCrumbs([{ text: "Settings" }]);

  const cur = h("input", { type: "password", autocomplete: "current-password", required: true });
  const nw = h("input", { type: "password", autocomplete: "new-password", required: true, minlength: "12" });
  const nw2 = h("input", { type: "password", autocomplete: "new-password", required: true });
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
      } catch (ex) { err.textContent = ex.message; }
    },
  },
    h("div", { class: "field" }, h("label", {}, "Current password"), cur),
    h("div", { class: "field" }, h("label", {}, "New password"), nw,
      h("div", { class: "hint" }, "12+ characters mixing letters, digits and symbols, or 16+ of anything.")),
    h("div", { class: "field" }, h("label", {}, "Confirm new password"), nw2),
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
      section("Export inventory", "Download every known device with its addresses, vendor, type and labels. Generated locally.",
        h("div", { class: "inline" },
          h("a", { class: "btn", href: "/api/export?format=csv", download: true }, icon("download"), "CSV"),
          h("a", { class: "btn", href: "/api/export?format=json", download: true }, icon("download"), "JSON"))),
    ),
  );
}

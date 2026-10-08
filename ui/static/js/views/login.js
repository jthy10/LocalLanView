import { state, h, icon, api } from "../lib.js";

export function renderLogin(root, message, onLogin) {
  const err = h("div", { class: "error", role: "alert" }, message || "");
  const user = h("input", { type: "text", id: "user", autocomplete: "username", required: true, value: "admin", spellcheck: "false" });
  const pass = h("input", { type: "password", id: "pass", autocomplete: "current-password", required: true });
  const btn = h("button", { class: "btn btn-primary", type: "submit" }, "Sign in");
  const form = h("form", {
    class: "login",
    onsubmit: async (e) => {
      e.preventDefault();
      btn.disabled = true;
      err.textContent = "";
      try {
        const r = await api("POST", "/api/login", { user: user.value.trim(), password: pass.value });
        state.csrf = r.csrf;
        state.user = r.user;
        state.generatedPassword = r.generatedPassword;
        onLogin();
      } catch (ex) {
        err.textContent = ex.message;
        pass.value = "";
        pass.focus();
      } finally {
        btn.disabled = false;
      }
    },
  },
    h("div", { class: "panel" },
      h("div", { class: "brand" }, icon("logo", "mark"), h("span", { class: "brand-name" }, "LocalLanView")),
      h("p", { class: "lead" }, "Sign in to the network console"),
      h("div", { class: "field" }, h("label", { for: "user" }, "Username"), user),
      h("div", { class: "field" }, h("label", { for: "pass" }, "Password"), pass),
      err,
      btn,
      h("p", { class: "hint" }, "First run? The password was printed once in the terminal where LocalLanView started."),
    ),
    h("div", { class: "foot" }, icon("lock"), "Runs on this machine. Nothing leaves your network."),
  );
  root.replaceChildren(h("div", { class: "login-page" }, form));
  pass.focus();
}

import { state, h, icon } from "../lib.js";
import { setCrumbs } from "../main.js";

// Plain links only: nothing on this page is fetched, the browser leaves
// only when someone clicks.
const REPO = "https://github.com/jthy10/LocalLanView";
const DEVELOPER = {
  name: "Jake Thygeson",
  links: [
    { icon: "github", text: "GitHub", href: "https://github.com/jthy10" },
    { icon: "globe", text: "jrtiv.com", href: "https://jrtiv.com" },
    { icon: "linkedin", text: "LinkedIn", href: "" },
  ],
};

const ABOUT = [
  "LocalLanView is a simple network scanner for home and small office networks. It shows what's connected, what each device probably is, and lets you know when something new shows up.",
  "It was made to give a clear picture of your own network without accounts, cloud services or telemetry. Everything runs on this machine and stays here.",
];

const ext = (href, kids, cls) => h("a", { class: cls, href, target: "_blank", rel: "noopener noreferrer" }, kids);

export function render(view) {
  setCrumbs([{ text: "About" }]);
  const version = (state.status && state.status.version) || "dev";
  const initials = DEVELOPER.name.split(" ").map((w) => w[0]).join("");

  view.replaceChildren(
    h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "About"))),
    h("div", { class: "about-page" },
      h("section", { class: "panel about-hero" },
        icon("logo", "about-mark"),
        h("div", { class: "t" },
          h("h2", {}, "LocalLanView"),
          h("div", { class: "muted" }, "Version ", h("span", { class: "mono" }, version))),
        h("div", { class: "about-copy" }, ABOUT.map((p) => h("p", {}, p))),
      ),
      h("div", { class: "cols even" },
        h("section", { class: "panel" },
          h("div", { class: "panel-head" }, h("h2", {}, icon("info"), "Developer")),
          h("div", { class: "panel-body dev" },
            h("span", { class: "avatar lg" }, initials),
            h("div", {},
              h("div", { class: "muted" }, "Developed by"),
              h("div", { class: "dev-name" }, DEVELOPER.name)),
          ),
          h("div", { class: "dev-links" }, DEVELOPER.links.filter((l) => l.href).map((l) =>
            ext(l.href, [icon(l.icon), l.text, icon("external", "ext")], "btn"))),
        ),
        h("section", { class: "panel" },
          h("div", { class: "panel-head" }, h("h2", {}, icon("layers"), "Project")),
          h("dl", { class: "kv" },
            h("dt", {}, "Source"), h("dd", {}, ext(REPO, "github.com/jthy10/LocalLanView")),
            h("dt", {}, "License"), h("dd", {}, "MIT"),
            h("dt", {}, "Privacy"), h("dd", {}, "No telemetry, no update checks, no outbound requests"),
            h("dt", {}, "Report an issue"), h("dd", {}, ext(REPO + "/issues", "GitHub issues"))),
        ),
      ),
    ),
  );
}

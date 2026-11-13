// The backoffice front end: one page, a view per hash route, everything read from and
// written through the backoffice API (api.js). No third-party code runs in the page: Vite
// only serves these modules in development and bundles them for dist/.
//
//   #/                    pairs and builders, with halt, resume, re-arm, delete, halt all,
//                         reload
//   #/pairs/new           a new pair
//   #/pairs/edit/<key>    one pair's stanza
//   #/builders/new        a new builder
//   #/settings            [settings], read-only, and which backoffice this page talks to
//
// When the backoffice takes a Google sign-in (auth.js), every route shows the sign-in until
// the operator has signed in.

import { api, apiBase, apiOverridden, configure, configuredBase, setApiBase } from "./api.js";
import * as auth from "./auth.js";
import { clear, h, shortAddress } from "./dom.js";
import { pairView } from "./pair.js";
import { go, notify, notifyError, notifyResult, onRerender, resultFlash, takeFlash } from "./ui.js";

const view = document.getElementById("view");
const apiLabel = document.getElementById("api-base");
const targetLabel = document.getElementById("target");
const whoTerm = document.getElementById("who-term");
const whoLabel = document.getElementById("who");

// ---------------------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------------------

let dispose = null;
let rendering = 0;
let showingSignIn = false;

function route(hash) {
  const path = hash.replace(/^#/, "") || "/";
  const edit = path.match(/^\/pairs\/edit\/(.+)$/);
  if (edit) return (root) => pairView(root, { key: decodeURIComponent(edit[1]) });
  if (path === "/pairs/new") return (root) => pairView(root, {});
  if (path === "/builders/new") return builderView;
  if (path === "/settings") return settingsView;
  return overview;
}

/** Renders the route into a fresh container. A view still loading when the route changes
 * again draws into a container no longer on the page, and its cleanup (the preview socket,
 * the polling) runs as soon as it returns. */
async function render() {
  const token = ++rendering;
  if (dispose) {
    try {
      dispose();
    } catch {
      // A cleanup that failed has nothing left to clean.
    }
    dispose = null;
  }
  const flash = takeFlash();
  if (flash) notify(...flash);
  else notify();
  const container = h("div", { class: "view" });
  clear(view).append(container);
  for (const link of document.querySelectorAll("nav a")) {
    link.classList.toggle("current", link.getAttribute("href") === (location.hash || "#/"));
  }
  let cleanup = null;
  showingSignIn = auth.required() && !auth.signedIn();
  try {
    cleanup = await (showingSignIn ? signInView : route(location.hash))(container);
  } catch (err) {
    if (token === rendering) {
      container.append(h("p", { class: "banner banner-err", role: "alert" }, err.message || String(err)));
    }
  }
  if (token === rendering) dispose = cleanup || null;
  else if (cleanup) cleanup();
}

// ---------------------------------------------------------------------------------------
// Pairs and builders
// ---------------------------------------------------------------------------------------

const STATUS = {
  live: ["live", "live"],
  halted: ["halted", "halted"],
  breaker_tripped: ["breaker tripped", "tripped"],
  not_running: ["not running", "idle"],
};

/** The pair's venues as the table shows them: `ETHUSDC` for the short form, and
 * `binance:ETHUSDC ×2 + kraken:ETH/USD ×1 (min 2)` for a list. */
function describeSources(pair) {
  if (pair.symbol) return pair.symbol;
  if (!pair.sources || pair.sources.length === 0) return null;
  const text = pair.sources
    .map((s) => `${s.venue.toLowerCase()}:${s.symbol} ×${s.weight || "1"}`)
    .join(" + ");
  return pair.min_sources ? `${text} (min ${pair.min_sources})` : text;
}

const unset = () => h("span", { class: "unset" }, "–");
const val = (text) => (text ? h("span", { class: "val" }, text) : unset());

/** Runs `call` from `button` after `question` is confirmed, with the button disabled while
 * it is under way, then says how it went and runs `after`. */
async function act(button, question, call, after) {
  if (question && !confirm(question)) return;
  button.disabled = true;
  try {
    notifyResult(await call());
  } catch (err) {
    notifyError(err);
  } finally {
    button.disabled = false;
  }
  if (after) await after();
}

function pairRow(view, refresh) {
  const { pair, status, pricing } = view;
  const key = pair.key_env;
  const [label, cls] = STATUS[status] || [status, "idle"];
  const band =
    pair.min_mid || pair.max_mid ? `${pair.min_mid || "*"}–${pair.max_mid || "*"}` : null;
  const toggle = pair.halted
    ? h("button", {
        type: "button",
        onclick: (e) =>
          act(e.currentTarget, `Resume ${key}? It starts quoting again at every builder.`, () => api.resume(key), refresh),
      }, "Resume")
    : h("button", {
        type: "button",
        onclick: (e) =>
          act(
            e.currentTarget,
            `Halt ${key}? Its quote is withdrawn at every builder, and it keeps its settings.`,
            () => api.halt(key),
            refresh,
          ),
      }, "Halt");
  // The one way back for a pair its circuit breaker halted: no reload, resume or edit
  // re-arms it (audit F-17). The answer names the price the restarted lane now trusts.
  const rearm =
    status === "breaker_tripped" &&
    h("button", {
      type: "button",
      title: "Restarts this pair's lane, which takes the price it finds now as its reference.",
      onclick: (e) =>
        act(
          e.currentTarget,
          `Re-arm ${key}? Its circuit breaker tripped. Re-arming restarts it, and it trusts the ` +
            "price it finds now as its reference: check the feed first.",
          () => api.rearm(key),
          refresh,
        ),
    }, "Re-arm");
  return h("tr", {},
    h("td", { class: "mono" },
      key,
      h("span", { class: `status ${cls}` }, label),
      pair.halt_reason && h("div", { class: "reason", title: "why it was halted" }, pair.halt_reason),
    ),
    h("td", { class: "addr" },
      (pair.tokens || []).flatMap((t, i) => (i ? [h("span", { class: "slash" }, "/"), shortAddress(t)] : [shortAddress(t)])),
    ),
    h("td", {}, val(describeSources(pair))),
    h("td", {}, val(pricing)),
    h("td", {}, val(band)),
    h("td", {}, val(pair.max_deviation)),
    h("td", { class: "rowactions" },
      h("a", { class: "btn", href: `#/pairs/edit/${encodeURIComponent(key)}` }, "Edit"),
      rearm,
      toggle,
      h("button", {
        type: "button",
        class: "danger",
        onclick: (e) =>
          act(e.currentTarget, `Remove ${key}? Its quote is withdrawn at every builder.`, () => api.removePair(key), refresh),
      }, "Delete"),
    ),
  );
}

function builderRow(builder, refresh) {
  const region =
    builder.disable_cross_region === true ? "cross-region off"
    : builder.disable_cross_region === false ? "cross-region on"
    : null;
  return h("tr", {},
    h("td", { class: "mono" }, builder.name),
    h("td", { class: "addr" }, h("code", {}, builder.endpoint)),
    h("td", {}, region ? val(region) : h("span", { class: "unset", title: "the global --disable-cross-region" }, "global")),
    h("td", { class: "rowactions" },
      h("button", {
        type: "button",
        class: "danger",
        onclick: (e) =>
          act(
            e.currentTarget,
            `Remove ${builder.name}? Every pair restarts onto the new list.`,
            () => api.removeBuilder(builder.name),
            refresh,
          ),
      }, "Delete"),
    ),
  );
}

/** How often the pair list is read again, for its statuses: a breaker trips on its own. */
const POLL_MS = 5000;

async function overview(root) {
  const pairsBox = h("div");
  const buildersBox = h("div");
  const refreshed = h("span", { class: "fieldhint" });

  // Redrawn only when something changed, so a poll never swaps a button out from under a
  // click or takes the focus away.
  let drawn = null;
  async function refreshPairs() {
    const pairs = await api.pairs();
    refreshed.textContent = `as of ${new Date().toLocaleTimeString()}`;
    const answer = JSON.stringify(pairs);
    if (answer === drawn) return;
    drawn = answer;
    clear(pairsBox).append(
      pairs.length === 0
        ? h("p", { class: "empty" }, "No pairs configured.")
        : h("table", {},
            h("thead", {}, h("tr", {}, ["key_env", "tokens", "source", "pricing", "band", "breaker", ""].map((t) => h("th", {}, t)))),
            h("tbody", {}, pairs.map((p) => pairRow(p, refreshAll))),
          ),
    );
  }

  async function refreshBuilders() {
    const builders = await api.builders();
    clear(buildersBox).append(
      builders.length === 0
        ? h("p", { class: "empty" }, "No builders configured.")
        : h("table", {},
            h("thead", {}, h("tr", {}, ["name", "endpoint", "cross-region", ""].map((t) => h("th", {}, t)))),
            h("tbody", {}, builders.map((b) => builderRow(b, refreshAll))),
          ),
    );
  }

  async function refreshAll() {
    try {
      await Promise.all([refreshPairs(), refreshBuilders()]);
    } catch (err) {
      notifyError(err);
    }
  }

  await Promise.all([refreshPairs(), refreshBuilders()]);

  root.append(
    h("div", { class: "toolbar" },
      h("button", {
        type: "button",
        class: "danger",
        onclick: (e) =>
          act(
            e.currentTarget,
            "Halt every pair? Each quote is withdrawn at every builder until someone restarts them.",
            api.haltAll,
            refreshAll,
          ),
      }, "Halt all pairs"),
      h("button", {
        type: "button",
        class: "primary",
        title:
          "Resumes the pairs halted from here and starts any pair that is not running. It re-arms " +
          "no tripped breaker: that is each pair's own Re-arm. A pair halted with a " +
          "reason (a binary's kill switch) resumes only from its own row.",
        onclick: (e) => act(e.currentTarget, null, api.reload, refreshAll),
      }, "Restart halted pairs"),
      refreshed,
    ),
    h("div", { class: "sectionhead" }, h("h2", {}, "Pairs"), h("a", { class: "btn", href: "#/pairs/new" }, "New pair")),
    pairsBox,
    h("div", { class: "sectionhead" }, h("h2", {}, "Builders"), h("a", { class: "btn", href: "#/builders/new" }, "New builder")),
    buildersBox,
  );

  // A failed read leaves the last table up and says so beside the time, rather than over
  // whatever the operator just did.
  const timer = setInterval(async () => {
    if (document.hidden) return;
    try {
      await refreshPairs();
    } catch (err) {
      refreshed.textContent = `refresh failed: ${err.message}`;
    }
  }, POLL_MS);
  return () => clearInterval(timer);
}

// ---------------------------------------------------------------------------------------
// A new builder
// ---------------------------------------------------------------------------------------

function field(name, input, hint) {
  return h("label", {}, h("span", { class: "key" }, name), input, hint && h("span", { class: "fieldhint" }, hint));
}

async function builderView(root) {
  const name = h("input", { type: "text", placeholder: "titan-eu", spellcheck: false, autocomplete: "off", required: true });
  const endpoint = h("input", {
    type: "text",
    placeholder: "wss://eu.rpc.titanbuilder.xyz/ws/sendquoteupdate",
    spellcheck: false,
    autocomplete: "off",
    required: true,
  });
  const key = h("input", { type: "password", autocomplete: "new-password", spellcheck: false, required: true });
  const region = h("select", {},
    h("option", { value: "" }, "the global --disable-cross-region"),
    h("option", { value: "true" }, "true: no cross-region"),
    h("option", { value: "false" }, "false: cross-region allowed"),
  );
  const save = h("button", { class: "primary" }, "Add builder");

  const form = h("form", { class: "card", novalidate: true },
    h("div", { class: "grid" },
      field("name", name, "how it appears in the logs; unique"),
      field("endpoint", endpoint, "maker WebSocket URL, ws:// or wss://"),
      field("api_key", key, "sent as the Authorization header; never shown again"),
      field("disable_cross_region", region, "blank follows the flag every builder shares"),
    ),
    h("div", { class: "actions" },
      h("span", { class: "spacer" }),
      h("a", { class: "btn", href: "#/" }, "Cancel"),
      save,
    ),
  );
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const builder = { name: name.value.trim(), endpoint: endpoint.value.trim(), api_key: key.value };
    if (!builder.name || !builder.endpoint || !builder.api_key) {
      notify("err", "A builder needs a name, an endpoint and an API key.");
      return;
    }
    if (region.value) builder.disable_cross_region = region.value === "true";
    save.disabled = true;
    try {
      go("#/", resultFlash(await api.addBuilder(builder)));
    } catch (err) {
      notifyError(err);
    } finally {
      save.disabled = false;
    }
  });

  root.append(
    h("header", { class: "pagehead" }, h("a", { class: "back", href: "#/" }, "← all builders"), h("h1", {}, "New builder")),
    h("p", { class: "warn" }, "Adding a builder restarts every pair onto the new list, and is refused if none of the builders would connect."),
    form,
  );
  name.focus();
}

// ---------------------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------------------

function settingValue(value) {
  if (value === null || value === undefined) return unset();
  if (typeof value === "string") return h("code", {}, value);
  if (Array.isArray(value)) return value.length ? h("code", {}, value.join(", ")) : unset();
  return h("code", {}, JSON.stringify(value));
}

async function settingsView(root) {
  root.append(
    h("header", { class: "pagehead" }, h("a", { class: "back", href: "#/" }, "← back"), h("h1", {}, "Settings")),
    connectionCard(),
  );
  let shown;
  try {
    shown = await api.settings();
  } catch (err) {
    root.append(h("p", { class: "banner banner-err", role: "alert" }, err.message));
    return;
  }
  const { endpoints, ...rest } = shown.settings || {};
  const rows = [
    ["config", shown.config_path],
    ["target", shown.target],
    ...Object.entries(rest),
  ];
  root.append(
    h("div", { class: "sectionhead" }, h("h2", {}, "config.toml")),
    h("p", { class: "warn" },
      "Read once, at start. To change one, edit ",
      h("code", {}, shown.config_path),
      " and restart the updater: the backoffice only shows them.",
    ),
    h("table", { class: "kv" },
      h("tbody", {}, rows.map(([k, v]) => h("tr", {}, h("th", { class: "mono" }, k), h("td", {}, settingValue(v))))),
    ),
    h("div", { class: "sectionhead" }, h("h2", {}, "Venue endpoints")),
    endpoints && Object.keys(endpoints).length
      ? h("table", { class: "kv" },
          h("tbody", {}, Object.entries(endpoints).map(([k, v]) => h("tr", {}, h("th", { class: "mono" }, k), h("td", {}, settingValue(v))))),
        )
      : h("p", { class: "empty" }, "Every venue at its own endpoint."),
  );
}

/** Which backoffice this page talks to: config.json's, or one saved on this browser. */
function connectionCard() {
  const input = h("input", {
    type: "text",
    value: apiOverridden() ? apiBase() : "",
    placeholder: configuredBase(),
    spellcheck: false,
    autocomplete: "off",
  });
  const form = h("form", { class: "card", novalidate: true },
    h("div", { class: "grid" },
      field("backoffice address", input,
        `Where this page sends its requests. Blank is ${configuredBase()}, from config.json beside ` +
          "this page (or the page's own address). Saved on this browser only. A backoffice at " +
          `another origin than this page's must list ${location.origin} with --backoffice-cors-origin.`),
    ),
    h("div", { class: "actions" }, h("span", { class: "spacer" }), h("button", { class: "primary" }, "Use this address")),
  );
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      setApiBase(input.value);
    } catch (err) {
      notifyError(err);
      return;
    }
    // Another backoffice may want a sign-in, or another one.
    await auth.start(api.auth);
    showConnection();
    showWho();
    go("#/settings", ["ok", `Talking to ${apiBase()}.`]);
  });
  return h("div", {}, h("div", { class: "sectionhead" }, h("h2", {}, "Connection")), form);
}

// ---------------------------------------------------------------------------------------
// Sign-in
// ---------------------------------------------------------------------------------------

/** What every route shows while the backoffice wants a sign-in and there is none. */
function signInView(root) {
  const button = h("div", { class: "signin-button" });
  root.append(
    h("header", { class: "pagehead" }, h("h1", {}, "Sign in")),
    h("div", { class: "card signin" },
      h("p", {}, `The backoffice at ${apiBase()} takes requests only from a Google account it allows. ` +
        "Sign in to see and change its pairs and builders."),
      auth.loadError() ? h("p", { class: "banner banner-err", role: "alert" }, auth.loadError()) : button,
      h("p", { class: "fieldhint" },
        "Google checks who you are; the backoffice checks that the account is one it lets in " +
          "(--backoffice-allow-domain, --backoffice-allow-email)."),
    ),
  );
  auth.renderButton(button);
}

/** The header's line saying who is signed in, with a way out; or a way in. Hidden when the
 * backoffice takes no sign-in. */
function showWho() {
  const on = auth.required();
  whoTerm.hidden = !on;
  whoLabel.hidden = !on;
  clear(whoLabel);
  if (!on) return;
  if (auth.signedIn()) {
    whoLabel.append(
      auth.signedInAs(), " ",
      h("button", { type: "button", class: "link", onclick: () => auth.signOut() }, "sign out"),
    );
  } else if (!showingSignIn) {
    const button = h("span", { class: "signin-button" });
    whoLabel.append(button);
    auth.renderButton(button, "small");
  } else {
    whoLabel.append("not signed in");
  }
}

// Set once the first view is drawn: until then, start draws it.
let booted = false;
// Whether a request was refused for a sign-in that ran out, for the line after the next one.
let lapsed = false;

auth.onChange((reason) => {
  if (!booted) return;
  if (reason === "expired") {
    // The view stays, with whatever was being typed: sign in again from the header and
    // retry what was refused.
    lapsed = true;
    showWho();
    notify("err", "Your sign-in has run out or was refused. Sign in again (top right), then retry.");
    return;
  }
  if (reason === "signed-in" && !showingSignIn) {
    // A renewal before the hour was up says nothing; a sign-in after a refusal says to retry.
    showWho();
    showConnection();
    if (lapsed) notify("ok", `Signed in again as ${auth.signedInAs()}. Retry what was refused.`);
    lapsed = false;
    return;
  }
  lapsed = false;
  // Sign-in turned on or off, a first sign-in, or a sign-out: the view changes with it.
  showConnection();
  render().then(showWho);
});

// ---------------------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------------------

/** The header's line saying which backoffice this is and what it quotes for. */
async function showConnection() {
  apiLabel.textContent = apiBase();
  apiLabel.title = apiOverridden() ? "saved on this browser (Settings)" : "from config.json";
  if (auth.required() && !auth.signedIn()) {
    targetLabel.textContent = "sign in to see";
    return;
  }
  targetLabel.textContent = "…";
  try {
    targetLabel.textContent = (await api.settings()).target;
  } catch {
    targetLabel.textContent = "unreachable";
  }
}

await configure();
await auth.start(api.auth);
showConnection();
const show = () => render().then(showWho);
onRerender(show);
window.addEventListener("hashchange", show);
booted = true;
render().then(showWho);

// A pair's form: new (`POST /api/pairs`) or one already configured (`PUT /api/pairs/{key}`).
//
// What the form sends is the pair's `[[pairs]]` stanza as JSON, with the keys config.toml
// uses. An edit starts from the stanza the API answered and changes only the keys this
// form has an input for, so whatever it has none for (a pricing key no field names, a key
// added later) goes back as it came, and opening a pair and saving it changes nothing.
// Blank inputs are left out rather than sent empty: every optional key is optional in the
// file too.
//
// The venue table is live, as the old server-rendered form's was:
//   1. Once both token addresses are in, GET /api/lookup fills it: which venues list the
//      pair, how each spells it, a weight from volume, and volume.
//   2. Each ticked venue gets its share of the weights, and a live mid over the preview
//      websocket (GET /api/preview): this page says which venues are ticked as that
//      changes, and the backoffice connects to exactly those with the code that would quote
//      them. The composite line is the number that would be published.
//   3. On save, an unticked venue is left out of `sources`.

import { api, socketProtocols, socketUrl } from "./api.js";
import { append, clear, h, helpFragment, isAddress, money } from "./dom.js";
import { go, notifyError, resultFlash } from "./ui.js";

/** The price source's bounds and the circuit breaker: keys of the pair, strings in the file. */
const SOURCE_FIELDS = [
  ["min_mid", "0.0001", "refuse a published mid below this"],
  ["max_mid", "0.001", "refuse a published mid above this"],
  ["max_deviation", "0.02", "circuit breaker: halt on a move this large"],
  ["max_deviation_window", "0.20", "circuit breaker: halt on this much total movement over the window below"],
  ["max_deviation_window_blocks", "1000", "how many blocks that window covers"],
  [
    "max_source_lag_ms",
    "1500",
    "leave a venue out of the average while its prices arrive more than this many milliseconds " +
      "behind the exchange's own timestamp; needs a venue that sends one (not binance, not mexc). " +
      "Blank is off",
  ],
];

const MIN_SOURCES_HINT =
  "how many of the venues above must have a fresh price for us to publish at all. Blank is 1: " +
  "keep quoting as long as any one venue is up";

/** What the table says beside a venue the lookup has nothing to say about. */
const VENUE_NOTES = {
  ondo:
    "Ondo's own price for one of its stock tokens, polled every second with the key in " +
    "ONDO_API_KEY; the symbol is the token's, e.g. AAPLon. It is one price with no spread: set a " +
    "delta in the pricing, or a blank one quotes at the mid",
};

/** How many venues a lookup ticks on a new pair: the ones with the most 24h volume. */
const TICK_TOP = 3;

/** The kind a new pair starts on, when the binary registers it. */
const DEFAULT_KIND = "feed";

/** A mid for reading: eight significant digits, so 2500.12 and 0.00038461 both read whole. */
const price = (n) => Number(n).toLocaleString("en-US", { maximumSignificantDigits: 8 });

const text = (attrs) =>
  h("input", { type: "text", spellcheck: false, autocomplete: "off", ...attrs });

const labelled = (name, input, hint) =>
  h("label", {}, h("span", { class: "key" }, name), input, hint && h("span", { class: "fieldhint" }, hint));

const optional = (input) => {
  const value = input.value.trim();
  return value === "" ? undefined : value;
};

function setOrDelete(obj, key, value) {
  if (value === undefined) delete obj[key];
  else obj[key] = value;
}

function parseJson(source, what) {
  try {
    return JSON.parse(source);
  } catch (err) {
    throw new Error(`${what} is not JSON: ${err.message}`);
  }
}

const isTable = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

export async function pairView(root, { key }) {
  const editing = key !== undefined;
  const [kinds, venues, current] = await Promise.all([
    api.kinds(),
    api.venues(),
    editing ? api.pair(key) : null,
  ]);
  const original = current ? current.pair : null;
  let disposed = false;

  // -------------------------------------------------------------------------------------
  // Identity: what the lane and the signer are derived from, so fixed once the pair exists.
  // -------------------------------------------------------------------------------------

  const token0 = text({ placeholder: "0xC02aaA39…", value: original?.tokens?.[0] ?? "", readOnly: editing });
  const token1 = text({ placeholder: "0xA0b86991…", value: original?.tokens?.[1] ?? "", readOnly: editing });
  const keyEnv = text({ placeholder: "UPDATER_KEY_WETH_USDC", value: original?.key_env ?? "", readOnly: editing });

  // -------------------------------------------------------------------------------------
  // The venue table
  // -------------------------------------------------------------------------------------

  const rows = venues.map((v, index) => {
    const row = {
      venue: v.venue,
      index,
      defaultNote: VENUE_NOTES[v.venue] || (v.polled ? "polled every second" : ""),
      tick: h("input", { type: "checkbox", "aria-label": `use ${v.venue}` }),
      symbol: text({ placeholder: v.example, "aria-label": `${v.venue} symbol` }),
      weight: text({ placeholder: "1", "aria-label": `${v.venue} weight` }),
      share: h("td", { class: "share" }),
      live: h("td", { class: "mid" }),
      volume: h("td", { class: "volume" }),
      note: h("td", { class: "note" }),
      listed: false,
      volumeUsd: null,
      autoSymbol: false,
      autoWeight: false,
      // Where it was in the saved `sources`, and how the file spelt its venue, so a save
      // writes the list back in its own order and spelling.
      savedAt: undefined,
      spelt: undefined,
    };
    row.note.textContent = row.defaultNote;
    row.tr = h("tr", {},
      h("td", { class: "tick" }, row.tick),
      h("td", { class: "mono" }, v.venue),
      h("td", {}, row.symbol),
      h("td", {}, row.weight),
      row.share, row.live, row.volume, row.note,
    );
    return row;
  });
  const byVenue = new Map(rows.map((r) => [r.venue, r]));

  // Sources naming a venue this binary does not list cannot be shown as a row; they are
  // kept as they are, after the rows, so a save does not drop them.
  const foreignSources = [];
  if (original?.symbol) {
    const binance = byVenue.get("binance");
    if (binance) {
      binance.symbol.value = original.symbol;
      binance.tick.checked = true;
    }
  }
  for (const [at, source] of (original?.sources || []).entries()) {
    const row = byVenue.get(String(source.venue).toLowerCase());
    if (!row) {
      foreignSources.push(source);
      continue;
    }
    row.symbol.value = source.symbol;
    row.weight.value = source.weight ?? "";
    row.tick.checked = true;
    row.savedAt = at;
    row.spelt = source.venue;
  }
  // The venues a saved pair already has: its first lookup keeps exactly those ticked (none,
  // for a pair with no venues) and leaves their symbols and weights alone, rather than
  // choosing its own, so opening a pair and saving it changes nothing.
  const saved = new Set(rows.filter((r) => r.tick.checked).map((r) => r.venue));

  const minSources = text({ placeholder: "1", value: original?.min_sources ?? "" });
  const sourceInputs = Object.fromEntries(
    SOURCE_FIELDS.map(([name, placeholder]) => [name, text({ placeholder, value: original?.[name] ?? "" })]),
  );

  const status = h("span", { class: "fieldhint", role: "status" });
  const lookupNotes = h("ul", { class: "notes", hidden: true });
  const compositeLine = h("p", { class: "notice", hidden: true, "aria-live": "polite" });
  const showUnlisted = h("input", { type: "checkbox" });

  function visibility() {
    // Never hide everything: a pair nobody lists still shows the table to fill by hand.
    const anyListed = rows.some((r) => r.listed);
    for (const row of rows) {
      row.tr.hidden = lookedUp && anyListed && !row.listed && !row.tick.checked && !showUnlisted.checked;
    }
  }

  function shares() {
    const ticked = rows.filter((r) => r.tick.checked);
    const weightOf = (r) => parseFloat(r.weight.value) || 1;
    const sum = ticked.reduce((acc, r) => acc + weightOf(r), 0);
    for (const row of rows) {
      row.share.textContent =
        row.tick.checked && sum > 0 ? `${((weightOf(row) / sum) * 100).toFixed(0)}%` : "";
    }
  }

  // -------------------------------------------------------------------------------------
  // The lookup
  // -------------------------------------------------------------------------------------

  let lookedUp = false;
  let lastLookup = "";
  async function lookup() {
    const a = token0.value.trim();
    const b = token1.value.trim();
    if (!isAddress(a) || !isAddress(b)) return;
    const asked = `${a}-${b}`.toLowerCase();
    if (asked === lastLookup) return;
    const first = lastLookup === "";
    lastLookup = asked;
    status.textContent = "looking up where this pair trades…";
    let data;
    try {
      data = await api.lookup(a, b);
    } catch (err) {
      if (!disposed && lastLookup === asked) {
        status.textContent = `lookup failed: ${err.message}`;
        lastLookup = "";
      }
      return;
    }
    // Answered after the page moved on, or after other tokens were typed.
    if (disposed || lastLookup !== asked) return;
    if (!data.ok) {
      status.textContent = `lookup failed: ${data.error}. Fill the table by hand.`;
      return;
    }
    lookedUp = true;
    // The pair is listed only the other way round (a token priced in USDC, never USDC
    // priced in the token) and the answer is for that orientation: on a new pair, put the
    // addresses that way too, since nothing depends on their order yet. A saved pair's
    // tokens cannot change, so it is only said.
    const swapped = data.swapped === true;
    if (swapped && !editing) {
      token0.value = b;
      token1.value = a;
      lastLookup = `${b}-${a}`.toLowerCase();
    }
    const keepSaved = first && editing;
    // Only markets in the pair's own quote are ticked. One in another dollar (`stand_in`) is
    // filled in but left to the operator, with its note saying why: averaged as if at par, it
    // fails the startup check unless the pair opts in (audit F-04).
    const top = new Set(
      data.venues
        .filter((v) => v.listed && !v.stand_in)
        .sort((x, y) => (y.volume_usd || 0) - (x.volume_usd || 0))
        .slice(0, TICK_TOP)
        .map((v) => v.venue),
    );
    for (const v of data.venues) {
      const row = byVenue.get(v.venue);
      if (!row) continue;
      row.listed = v.listed;
      row.volumeUsd = v.volume_usd;
      const keep = keepSaved && saved.has(v.venue);
      if (!v.listed) {
        // What an earlier lookup filled in is not an operator's choice: an unlisted venue
        // loses its filled-in symbol and its tick.
        if (row.autoSymbol) {
          row.symbol.value = "";
          row.autoSymbol = false;
        }
        if (row.autoWeight) {
          row.weight.value = "";
          row.autoWeight = false;
        }
        if (!row.symbol.value.trim()) row.tick.checked = false;
      } else if (!keep) {
        // Fill what the operator has not typed; never overwrite an edited symbol.
        if (!row.symbol.value.trim() || row.autoSymbol) {
          row.symbol.value = v.symbol;
          row.autoSymbol = true;
        }
        if (!row.weight.value.trim() || row.autoWeight) {
          row.weight.value = v.weight ?? "";
          row.autoWeight = true;
        }
        row.tick.checked = keepSaved ? false : top.has(v.venue);
      }
      // An exchange that did not answer may well list the pair; say that, not "not listed".
      row.volume.textContent = v.volume_usd
        ? money(v.volume_usd)
        : v.listed ? "" : v.unreachable ? "couldn't reach it" : "not listed";
      row.note.textContent = v.note || row.defaultNote;
    }
    const listed = data.venues.filter((v) => v.listed).length;
    status.textContent =
      `${data.base}/${data.quote}` +
      (swapped && !editing ? ` (swapped: venues price ${data.base} in ${data.quote}, not the other way round)` : "") +
      (swapped && editing ? ` (venues price ${data.base} in ${data.quote}, the other way round from this pair's tokens)` : "") +
      (listed === 0 ? " (no venue lists this pair; fill the table by hand)" : "") +
      (listed > 0 && top.size === 0 && !keepSaved
        ? ` (venues list ${data.base} only against another dollar, so none is ticked; see each venue's note)`
        : "");
    append(clear(lookupNotes), (data.notes || []).map((n) => h("li", {}, n)));
    lookupNotes.hidden = !(data.notes || []).length;
    visibility();
    shares();
    sync();
  }

  // -------------------------------------------------------------------------------------
  // Live prices: one websocket for as long as the form is open. It is told which venues
  // are ticked one change at a time ("set" a venue's symbol and weight, "remove" it), and
  // connects to exactly those; twice a second it sends every ticked venue's mid and the
  // composite. The backoffice allows four open at once, so leaving the form closes it.
  // -------------------------------------------------------------------------------------

  let socket = null;
  let socketTokens = "";
  let reopenTimer = null;
  let syncTimer = null;
  // What the socket has been told, by venue: {symbol, weight}.
  let sent = new Map();
  // An error the socket answered a command with, shown under the composite for a while
  // rather than for the half second until the next snapshot.
  let previewError = null;

  const tokensKey = () => `${token0.value.trim()}-${token1.value.trim()}`.toLowerCase();

  function closeSocket() {
    if (!socket) return;
    const ws = socket;
    socket = null;
    ws.onclose = null;
    ws.onmessage = null;
    // One still connecting is closed once it opens: closing it mid-handshake aborts the
    // connection, which the browser reports as an error. Opened, it connects to no venue
    // and holds its preview slot only until this close.
    if (ws.readyState === WebSocket.CONNECTING) ws.onopen = () => ws.close();
    else {
      ws.onopen = null;
      ws.close();
    }
  }

  function showComposite(line) {
    const error = previewError && previewError.until > Date.now() ? previewError.text : null;
    compositeLine.hidden = !line && !error;
    compositeLine.textContent = [line, error && `live prices: ${error}`].filter(Boolean).join(" · ");
  }

  function openSocket() {
    clearTimeout(reopenTimer);
    closeSocket();
    sent = new Map();
    for (const row of rows) row.live.textContent = "";
    showComposite(null);
    // Recorded even when they are not addresses yet, so typing them does not reopen this.
    socketTokens = tokensKey();
    if (disposed || !isAddress(token0.value) || !isAddress(token1.value)) return;
    const query = `token0=${encodeURIComponent(token0.value.trim())}&token1=${encodeURIComponent(token1.value.trim())}`;
    let ws;
    try {
      ws = new WebSocket(socketUrl(`/api/preview?${query}`), socketProtocols());
    } catch (err) {
      showComposite(`live prices unavailable: ${err.message}`);
      return;
    }
    socket = ws;
    ws.onopen = () => sync(0);
    ws.onmessage = (event) => {
      let data;
      try {
        data = JSON.parse(event.data);
      } catch {
        return;
      }
      if (data.error) {
        previewError = { text: data.error, until: Date.now() + 6000 };
        showComposite(compositeLine.dataset.line || null);
        return;
      }
      const seen = new Set();
      for (const v of data.venues) {
        const row = byVenue.get(v.venue);
        if (!row) continue;
        seen.add(v.venue);
        row.live.textContent =
          v.mid === null
            ? v.age_ms === null ? "connecting…" : "no price"
            : price(v.mid) + (v.fresh ? "" : " (stale)");
        row.live.classList.toggle("stale", v.mid !== null && !v.fresh);
      }
      for (const row of rows) {
        if (!seen.has(row.venue)) row.live.textContent = sent.has(row.venue) ? "connecting…" : "";
      }
      const line =
        data.venues.length === 0 ? ""
        : data.composite === null ? `composite: waiting for a fresh venue (${data.fresh} fresh)`
        : `composite mid ${price(data.composite)} from ${data.fresh} fresh venue${data.fresh === 1 ? "" : "s"}: ` +
          "this is the number that would be published";
      compositeLine.dataset.line = line;
      showComposite(line);
    };
    // Dropped, or refused (four previews already open, or this page's origin not listed):
    // try again in a few seconds, telling it the ticked venues afresh. Opening the socket
    // connects to no venue by itself.
    ws.onclose = () => {
      if (socket !== ws) return;
      socket = null;
      showComposite("live prices dropped; reconnecting in 5s");
      reopenTimer = setTimeout(openSocket, 5000);
    };
  }

  /** Tells the socket what changed since the last time: new or edited venues are "set",
   * unticked ones "remove". Waits for typing to stop, so a symbol typed letter by letter is
   * sent once. New tokens open a new socket instead. */
  function sync(delay = 600) {
    clearTimeout(syncTimer);
    syncTimer = setTimeout(() => {
      if (disposed) return;
      if (tokensKey() !== socketTokens) {
        openSocket();
        return;
      }
      if (!socket || socket.readyState !== WebSocket.OPEN) return;
      const want = new Map();
      for (const row of rows) {
        const symbol = row.symbol.value.trim();
        if (row.tick.checked && symbol) want.set(row.venue, { symbol, weight: row.weight.value.trim() || "1" });
      }
      for (const venue of sent.keys()) {
        if (!want.has(venue)) {
          socket.send(JSON.stringify({ type: "remove", venue }));
          byVenue.get(venue).live.textContent = "";
        }
      }
      for (const [venue, v] of want) {
        const was = sent.get(venue);
        if (!was || was.symbol !== v.symbol || was.weight !== v.weight) {
          socket.send(JSON.stringify({ type: "set", venue, symbol: v.symbol, weight: v.weight }));
        }
      }
      sent = want;
    }, delay);
  }

  // -------------------------------------------------------------------------------------
  // Pricing: one section per registered kind, the chosen one shown. A kind with fields is
  // a form; one with none (or one the pair names that this binary does not register) is
  // the rest of its stanza as JSON.
  // -------------------------------------------------------------------------------------

  const registered = kinds.map((k) => k.kind);
  const savedKind = original?.pricing?.kind;
  let chosen = savedKind ?? (registered.includes(DEFAULT_KIND) ? DEFAULT_KIND : registered[0]);
  const kindList = kinds.map((k) => ({ ...k, fields: k.fields || [] }));
  if (savedKind && !registered.includes(savedKind)) {
    kindList.push({ kind: savedKind, help_html: "", fields: [], unregistered: true });
  }

  const pricing = kindList.map((spec) => {
    const ours = savedKind === spec.kind ? original.pricing : null;
    const radio = h("input", { type: "radio", name: "pricing-kind", value: spec.kind, checked: spec.kind === chosen });
    const card = h("label", { class: "choice" }, radio, h("span", { class: "choice-name" }, spec.kind));
    const section = h("div", { class: "pricing-section", hidden: spec.kind !== chosen });
    section.append(helpFragment(spec.help_html));
    const entry = { spec, ours, radio, card, section, inputs: [], json: null };
    if (spec.unregistered) {
      section.append(h("p", { class: "warn" },
        "This binary registers no pricing kind ",
        h("code", {}, spec.kind),
        ", so the reload will refuse this pair until it does or another kind is chosen."));
    }
    if (spec.fields.length) {
      entry.inputs = spec.fields.map((field) => {
        const was = ours ? ours[field.name] : undefined;
        const input = text({
          placeholder: field.placeholder,
          value: was === undefined ? "" : typeof was === "string" ? was : JSON.stringify(was),
        });
        return { field, input };
      });
      section.append(h("div", { class: "grid" },
        entry.inputs.map(({ field, input }) => labelled(field.name, input, field.hint))));
      const extra = ours ? Object.keys(ours).filter((k) => k !== "kind" && !spec.fields.some((f) => f.name === k)) : [];
      if (extra.length) {
        section.append(h("p", { class: "explain" },
          "Also in this pair's stanza, kept as written: ",
          extra.map((k, i) => [i ? ", " : "", h("code", {}, k)])));
      }
    } else {
      const { kind: _kind, ...rest } = ours || {};
      entry.json = h("textarea", {
        rows: 6,
        spellcheck: false,
        placeholder: '{"mid": "1.0", "delta": "0.0005"}',
        value: Object.keys(rest).length ? JSON.stringify(rest, null, 2) : "",
      });
      section.append(
        h("p", { class: "explain" },
          h("code", {}, spec.kind),
          " has no form: write the rest of its ",
          h("code", {}, "[pairs.pricing]"),
          " stanza, everything but ",
          h("code", {}, "kind"),
          ", as a JSON object."),
        entry.json,
      );
    }
    radio.addEventListener("change", () => {
      chosen = spec.kind;
      for (const other of pricing) {
        other.section.hidden = other !== entry;
        other.card.classList.toggle("selected", other === entry);
      }
    });
    card.classList.toggle("selected", spec.kind === chosen);
    return entry;
  });

  function buildPricing() {
    const entry = pricing.find((p) => p.spec.kind === chosen);
    if (!entry) throw new Error("Choose a pricing kind.");
    const { spec, ours } = entry;
    if (entry.json === null) {
      // Starts from the saved stanza when the kind is the same, so a key no field names is
      // kept; a value the operator did not change keeps its saved type.
      const table = ours ? structuredClone(ours) : { kind: spec.kind };
      for (const { field, input } of entry.inputs) {
        const raw = input.value.trim();
        const was = ours ? ours[field.name] : undefined;
        const shown = was === undefined ? "" : typeof was === "string" ? was : JSON.stringify(was);
        if (raw === "") delete table[field.name];
        else if (was !== undefined && raw === shown) table[field.name] = was;
        else if (field.number) {
          const n = Number(raw);
          if (!Number.isFinite(n)) throw new Error(`${spec.kind}: ${field.name} must be a number.`);
          table[field.name] = n;
        } else table[field.name] = raw;
      }
      return table;
    }
    const source = entry.json.value.trim();
    const rest = source ? parseJson(source, `${spec.kind}'s stanza`) : {};
    if (!isTable(rest)) throw new Error(`${spec.kind}'s stanza must be a JSON object.`);
    if ("kind" in rest && rest.kind !== spec.kind) {
      throw new Error(`${spec.kind}'s stanza names kind ${JSON.stringify(rest.kind)}; choose that kind instead.`);
    }
    const { kind: _kind, ...others } = rest;
    return { kind: spec.kind, ...others };
  }

  // -------------------------------------------------------------------------------------
  // Guards: no route lists the registered guard kinds, so they are written as their
  // `[[pairs.guards]]` stanzas, a JSON list.
  // -------------------------------------------------------------------------------------

  const guards = h("textarea", {
    rows: 4,
    spellcheck: false,
    placeholder: '[{"kind": "venue_spread", "max_spread": "0.01"}]',
    value: original?.guards?.length ? JSON.stringify(original.guards, null, 2) : "",
  });
  const mismatch = h("input", { type: "checkbox", checked: Boolean(original?.allow_symbol_mismatch) });

  // -------------------------------------------------------------------------------------
  // The stanza
  // -------------------------------------------------------------------------------------

  function buildPair() {
    const pair = original ? structuredClone(original) : {};
    if (!original) {
      const t0 = token0.value.trim();
      const t1 = token1.value.trim();
      if (!isAddress(t0) || !isAddress(t1)) {
        throw new Error("token0 and token1 must be addresses: 0x and 40 hex digits.");
      }
      const k = keyEnv.value.trim();
      if (!k) throw new Error("key_env names the variable that holds this pair's key; it cannot be blank.");
      pair.tokens = [t0, t1];
      pair.key_env = k;
    }

    for (const row of rows) {
      if (row.tick.checked && !row.symbol.value.trim() && row.weight.value.trim()) {
        throw new Error(`${row.venue} has a weight but no symbol; fill in the market to use it, or clear the weight.`);
      }
    }
    const order = (r) => (r.savedAt === undefined ? Infinity : r.savedAt);
    const used = rows
      .filter((r) => r.tick.checked && r.symbol.value.trim())
      .sort((a, b) => order(a) - order(b) || a.index - b.index);
    const list = used.map((r) => {
      const source = { venue: r.spelt || r.venue, symbol: r.symbol.value.trim() };
      const weight = r.weight.value.trim();
      if (weight) source.weight = weight;
      return source;
    });
    list.push(...foreignSources);
    const min = optional(minSources);
    delete pair.symbol;
    delete pair.sources;
    delete pair.min_sources;
    // One Binance market with no weight and no minimum is `symbol`, the short form, unless
    // the pair was saved with the list: either way a pair saved untouched reads back as it was.
    const keptList = Boolean(original?.sources?.length);
    const [only] = list;
    if (!keptList && list.length === 1 && only.venue.toLowerCase() === "binance" && !only.weight && min === undefined) {
      pair.symbol = only.symbol;
    } else {
      if (list.length) pair.sources = list;
      setOrDelete(pair, "min_sources", min);
    }

    for (const [name] of SOURCE_FIELDS) setOrDelete(pair, name, optional(sourceInputs[name]));

    pair.pricing = buildPricing();

    const guardText = guards.value.trim();
    const guardList = guardText ? parseJson(guardText, "guards") : [];
    if (!Array.isArray(guardList) || !guardList.every((g) => isTable(g) && typeof g.kind === "string")) {
      throw new Error('guards must be a JSON list of objects, each with its "kind".');
    }
    setOrDelete(pair, "guards", guardList.length ? guardList : undefined);

    setOrDelete(pair, "allow_symbol_mismatch", mismatch.checked ? true : undefined);
    return pair;
  }

  // -------------------------------------------------------------------------------------
  // The page
  // -------------------------------------------------------------------------------------

  const bodyView = h("pre", { class: "json" });
  const bodyBox = h("details", { class: "body" },
    h("summary", {}, editing ? `The request: PUT /api/pairs/${key}` : "The request: POST /api/pairs"),
    bodyView,
  );
  function showBody() {
    if (!bodyBox.open) return;
    try {
      bodyView.textContent = JSON.stringify(buildPair(), null, 2);
      bodyView.classList.remove("bad");
    } catch (err) {
      bodyView.textContent = err.message;
      bodyView.classList.add("bad");
    }
  }
  bodyBox.addEventListener("toggle", showBody);

  const save = h("button", { class: "primary" }, editing ? "Save" : "Add pair");
  const form = h("form", { class: "card", novalidate: true },
    h("div", { class: "grid" },
      labelled("token0", token0, "base token, market orientation"),
      labelled("token1", token1, "quote token"),
      labelled("key_env", keyEnv, "variable holding this pair's key"),
    ),
    editing && h("p", { class: "fieldhint" },
      "A pair's tokens and key_env are what its lane and signer are derived from: a pair on others is a delete and an add."),
    h("hr"),
    h("div", { class: "sources" },
      h("span", { class: "key" }, "mid sources"),
      h("p", { class: "explain" },
        "A venue that goes quiet drops out of the average until it is back. Leave every venue unticked for a " +
          "fixed mid, or for a pricing kind that brings its own mid. A stock pair's venue is ",
        h("code", {}, "ondo"),
        ", the issuer's own price for the token."),
      h("div", { class: "venue-tools" },
        status,
        h("span", { class: "venue-buttons" },
          h("button", { type: "button", onclick: weightsByVolume }, "weights by volume"),
          h("button", { type: "button", onclick: equalWeights }, "equal weights"),
          h("label", { class: "check" }, showUnlisted, "show unlisted venues"),
        ),
      ),
      lookupNotes,
      compositeLine,
      h("div", { class: "scroll" },
        h("table", { class: "venues" },
          h("thead", {}, h("tr", {}, ["", "venue", "symbol", "weight", "share", "live mid", "24h volume", ""].map((t) => h("th", {}, t)))),
          h("tbody", {}, rows.map((r) => r.tr)),
        ),
      ),
      h("div", { class: "grid" },
        labelled("min_sources", minSources, MIN_SOURCES_HINT),
        SOURCE_FIELDS.map(([name, , hint]) => labelled(name, sourceInputs[name], hint)),
      ),
    ),
    h("hr"),
    h("div", { class: "pricing" },
      h("span", { class: "key" }, "pricing"),
      h("div", { class: "pricing-choice" }, pricing.map((p) => p.card)),
      pricing.map((p) => p.section),
    ),
    h("hr"),
    h("div", { class: "guards" },
      h("span", { class: "key" }, "guards"),
      h("p", { class: "explain" },
        "The pair's ",
        h("code", {}, "[[pairs.guards]]"),
        " stanzas as a JSON list, each with the ",
        h("code", {}, "kind"),
        " the binary registered it as. Blank is none."),
      guards,
    ),
    bodyBox,
    h("div", { class: "actions" },
      h("label", { class: "check" }, mismatch, "allow_symbol_mismatch"),
      h("a", { class: "btn", href: "#/" }, "Cancel"),
      save,
    ),
  );
  form.addEventListener("input", showBody);
  form.addEventListener("change", showBody);

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    let pair;
    try {
      pair = buildPair();
    } catch (err) {
      notifyError(err);
      return;
    }
    save.disabled = true;
    try {
      if (editing) {
        // The halt is not this form's to change, and may have changed since the page
        // loaded (a breaker, a kill switch, another operator): send it as it is now, so the
        // edit neither lifts nor sets one.
        const now = (await api.pair(key)).pair;
        setOrDelete(pair, "halted", now.halted);
        setOrDelete(pair, "halt_reason", now.halt_reason);
      }
      const result = editing ? await api.editPair(key, pair) : await api.addPair(pair);
      go("#/", resultFlash(result));
    } catch (err) {
      notifyError(err);
    } finally {
      save.disabled = false;
    }
  });

  function equalWeights() {
    for (const row of rows) {
      if (!row.tick.checked) continue;
      row.weight.value = "1";
      row.autoWeight = false;
    }
    shares();
    sync();
    showBody();
  }

  function weightsByVolume() {
    const ticked = rows.filter((r) => r.tick.checked && r.volumeUsd);
    const max = Math.max(0, ...ticked.map((r) => r.volumeUsd));
    for (const row of rows) {
      if (!row.tick.checked) continue;
      row.weight.value =
        row.volumeUsd && max > 0 ? String(Math.max(1, Math.round((row.volumeUsd / max) * 100) / 10)) : "1";
      row.autoWeight = false;
    }
    shares();
    sync();
    showBody();
  }

  for (const row of rows) {
    row.tick.addEventListener("change", () => {
      visibility();
      shares();
      sync();
    });
    row.symbol.addEventListener("input", () => {
      row.autoSymbol = false;
      if (row.symbol.value.trim()) row.tick.checked = true;
      shares();
      sync();
    });
    row.weight.addEventListener("input", () => {
      row.autoWeight = false;
      shares();
      sync();
    });
  }
  showUnlisted.addEventListener("change", visibility);
  for (const input of [token0, token1]) {
    input.addEventListener("change", () => {
      lookup();
      sync();
    });
  }

  const statusLine = current && h("p", { class: "meta-line" },
    h("span", { class: `status ${current.status === "live" ? "live" : current.status === "not_running" ? "idle" : current.status === "breaker_tripped" ? "tripped" : "halted"}` },
      current.status.replace("_", " ")),
    " ",
    h("span", { class: "val" }, current.pricing),
    original.halt_reason && h("span", { class: "reason" }, ` halted: ${original.halt_reason}`),
  );

  append(root, [
    h("header", { class: "pagehead" },
      h("a", { class: "back", href: "#/" }, "← all pairs"),
      h("h1", {}, editing ? `Edit ${key}` : "New pair"),
      statusLine,
    ),
    !editing && h("p", { class: "warn" },
      "Its ",
      h("code", {}, "key_env"),
      " has to be in the updater's environment already. The environment is read once, at start, so a brand " +
        "new key needs a redeploy."),
    editing && original.halted && h("p", { class: "warn" },
      "This pair is halted. Saving keeps it halted; resume it from the list of pairs."),
    form,
    editing && h("div", { class: "removal" },
      h("button", {
        type: "button",
        class: "danger",
        onclick: async (e) => {
          const button = e.currentTarget;
          if (!confirm(`Remove ${key}? Its quote is withdrawn at every builder.`)) return;
          button.disabled = true;
          try {
            go("#/", resultFlash(await api.removePair(key)));
          } catch (err) {
            notifyError(err);
            button.disabled = false;
          }
        },
      }, "Delete this pair"),
    ),
  ]);

  visibility();
  shares();
  lookup();
  sync(0);
  if (!editing) token0.focus();

  return () => {
    disposed = true;
    clearTimeout(syncTimer);
    clearTimeout(reopenTimer);
    closeSocket();
  };
}

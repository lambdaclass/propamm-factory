// Building the page. Every element is made with createElement and every string goes in as
// text, so nothing the API or an exchange answers (a symbol, a note, a halt reason, an
// error) is ever parsed as HTML. The one exception is a pricing kind's help, which the
// binary writes as HTML on purpose; it goes through `helpFragment`, an allowlist.

/** `h("td", {class: "mono"}, "text", child)`. Attributes that are properties of the element
 * (`value`, `checked`, `disabled`, `readOnly`, `spellcheck`...) are set as properties, so
 * `false` means false; `on*` functions become listeners. Any other attribute is set as
 * written, `true` as present and `false`, `null` or `undefined` as absent. */
export function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === undefined || value === null) continue;
    if (key === "class") el.className = value;
    else if (key === "for") el.htmlFor = value;
    else if (key === "dataset") Object.assign(el.dataset, value);
    else if (key.startsWith("on") && typeof value === "function") {
      el.addEventListener(key.slice(2), value);
    } else if (key in el && !key.includes("-")) el[key] = value;
    else if (value !== false) el.setAttribute(key, value === true ? "" : String(value));
  }
  append(el, children);
  return el;
}

/** Appends strings as text and nodes as they are; nested arrays are flattened, and `null`,
 * `undefined` and `false` skipped, so a child can be written `cond && h(...)`. */
export function append(parent, children) {
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    parent.append(child instanceof Node ? child : String(child));
  }
  return parent;
}

export function clear(el) {
  el.replaceChildren();
  return el;
}

// The tags a kind's help is written with (`pricing/*.rs`, `form_help`), and the one
// attribute kept, `class`, which style.css styles. Anything else is unwrapped to its text,
// and these are dropped with their contents.
const HELP_TAGS = new Set([
  "P", "B", "I", "EM", "STRONG", "CODE", "DIV", "SPAN", "BR", "UL", "OL", "LI", "SUB", "SUP", "SMALL",
]);
const HELP_DROPPED = new Set(["SCRIPT", "STYLE", "TEMPLATE", "IFRAME", "OBJECT", "EMBED", "NOSCRIPT"]);

/** A kind's `help_html` from `GET /api/kinds`, rebuilt from an allowlist: the tags above
 * with their `class`, nothing else. Parsed with DOMParser, which runs no script and loads
 * nothing, then copied node by node into this document. */
export function helpFragment(html) {
  const parsed = new DOMParser().parseFromString(`<body>${html || ""}`, "text/html");
  const out = document.createDocumentFragment();
  const copy = (from, to) => {
    for (const node of from.childNodes) {
      if (node.nodeType === Node.TEXT_NODE) {
        to.append(node.textContent);
      } else if (node.nodeType === Node.ELEMENT_NODE && !HELP_DROPPED.has(node.tagName)) {
        if (HELP_TAGS.has(node.tagName)) {
          const el = document.createElement(node.tagName.toLowerCase());
          const cls = node.getAttribute("class");
          if (cls) el.className = cls;
          copy(node, el);
          to.append(el);
        } else {
          copy(node, to);
        }
      }
    }
  };
  copy(parsed.body, out);
  return out;
}

/** `0xC02a…6Cc2`, with the whole address in the tooltip. */
export function shortAddress(address) {
  const a = String(address || "");
  return h("code", { title: a }, a.length > 12 ? `${a.slice(0, 6)}…${a.slice(-4)}` : a);
}

export const isAddress = (s) => /^0x[0-9a-fA-F]{40}$/.test(String(s || "").trim());

/** A number for reading, not for sending: grouped, at most `digits` decimals. */
export const fmt = (n, digits) =>
  n === null || n === undefined ? "" : Number(n).toLocaleString("en-US", { maximumFractionDigits: digits });

export const money = (v) =>
  v >= 1e9 ? `$${(v / 1e9).toFixed(1)}B`
  : v >= 1e6 ? `$${(v / 1e6).toFixed(1)}M`
  : v >= 1e3 ? `$${(v / 1e3).toFixed(0)}k`
  : `$${Number(v).toFixed(0)}`;

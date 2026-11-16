// What every view shares: the banner above it and moving between views.

import { clear, h } from "./dom.js";

const flashBox = document.getElementById("flash");

/** A banner above the view: `ok`, `warn` (a change kept in part) or `err`. No text clears it. */
export function notify(kind, text) {
  clear(flashBox);
  if (!text) return;
  flashBox.append(
    h("p", { class: `banner banner-${kind}`, role: kind === "err" ? "alert" : "status" }, text),
  );
  flashBox.scrollIntoView({ block: "nearest" });
}

/** A change's answer as a banner's [kind, text]: `applied` is a success; `partial` is kept,
 * but some pair still runs its previous config, which deserves more than a green banner. */
export function resultFlash(result) {
  return result.status === "partial"
    ? ["warn", `Kept, but applied only in part: ${result.message}`]
    : ["ok", result.message];
}

export const notifyResult = (result) => notify(...resultFlash(result));

export const notifyError = (err) => notify("err", err && err.message ? err.message : String(err));

let pending = null;
let rerender = () => {};

/** Goes to `hash`, with `flash` ([kind, text]) shown on arrival. */
export function go(hash, flash) {
  pending = flash || null;
  if (location.hash === hash) rerender();
  else location.hash = hash;
}

/** For the router: what `go` asked to show on arrival, once. */
export function takeFlash() {
  const flash = pending;
  pending = null;
  return flash;
}

/** For the router: what `go` calls when the hash it is given is already the current one. */
export function onRerender(fn) {
  rerender = fn;
}

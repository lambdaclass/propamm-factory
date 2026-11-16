// Google sign-in, when the backoffice asks for it. It says so at `GET /api/auth`:
// `{"google_client_id": "..."}`, or `null` when it takes no sign-in. A backoffice from before
// sign-in has no such route and answers 404, which reads as none.
//
// With a client ID, this loads Google's own sign-in script (Google Identity Services, from
// accounts.google.com: the one thing this page loads from another site, see index.html's
// Content-Security-Policy), signs the operator in, and keeps the ID token Google hands it in
// memory only. Every request carries it as `Authorization: Bearer` (api.js), and the preview
// socket as a subprotocol, since a browser cannot give a websocket a header. The token is
// also kept in sessionStorage, so a reload of this tab stays signed in: Google gives a token
// without a click only now and then (not twice within ten minutes, not after a dismissed
// prompt). It goes when the tab closes, on sign-out, and when the backoffice refuses it.
//
// An ID token is good for about an hour. Two minutes before it runs out, Google is asked for
// a new one, which it gives without a click when it can. When it cannot, the next request
// answers 401, the token is dropped, and the header's button signs in again.

const GSI = "https://accounts.google.com/gsi/client";
const RENEW_EARLY_MS = 2 * 60 * 1000;
const KEPT = "backoffice.signin";

let ask = null;
let clientId = null;
let gsi = null; // google.accounts.id, once loaded and initialized
let gsiError = null;
let token = null;
let who = null;
let renewTimer = null;
const listeners = new Set();

/** Whether the backoffice takes requests only from a signed-in account. */
export const required = () => clientId !== null;
export const signedIn = () => token !== null;
/** The signed-in address, as the token says. */
export const signedInAs = () => who;
/** The ID token requests carry, or null. */
export const currentToken = () => token;
/** Why Google's sign-in could not be loaded, or null. */
export const loadError = () => gsiError;

/** `fn(reason)` on every change: "required" (the backoffice asks for sign-in, or stopped
 * asking), "signed-in", "signed-out", "expired". */
export function onChange(fn) {
  listeners.add(fn);
}

function changed(reason) {
  for (const fn of listeners) fn(reason);
}

/** Asks the backoffice whether it takes a sign-in (`fetchAuth` is `api.auth`) and, when it
 * does, gets Google's script ready and tries a sign-in without a click. Called at start and
 * whenever the page is pointed at another backoffice. */
export async function start(fetchAuth) {
  ask = fetchAuth;
  // Maybe another backoffice: nothing of the last one's is kept, its token least of all,
  // which would otherwise go out on the very request asking the new one.
  const before = clientId;
  clientId = null;
  forget();
  gsiError = null;
  await discover();
  if (before !== null && clientId === null) changed("required");
}

async function discover() {
  let next;
  try {
    const answer = await ask();
    next = answer && typeof answer.google_client_id === "string" ? answer.google_client_id : null;
  } catch (err) {
    // 404 is a backoffice from before sign-in. Anything else (down, not listing this page's
    // origin) says nothing either way: keep what is known, and let the views say why.
    if (err && err.status === 404) next = null;
    else return;
  }
  if (next === clientId) return;
  clientId = next;
  forget();
  gsiError = null;
  if (clientId) {
    try {
      await ready();
      if (!restore()) gsi.prompt();
    } catch (err) {
      gsiError = err.message || String(err);
    }
  }
  changed("required");
}

async function ready() {
  if (!(window.google && window.google.accounts && window.google.accounts.id)) {
    await new Promise((resolve, reject) => {
      const script = document.createElement("script");
      script.src = GSI;
      script.async = true;
      script.onload = resolve;
      script.onerror = () =>
        reject(
          new Error(
            "Could not load Google's sign-in from accounts.google.com, which this backoffice " +
              "needs. Is it blocked here (an extension, a proxy, no internet)?",
          ),
        );
      document.head.append(script);
    });
  }
  gsi = window.google.accounts.id;
  gsi.initialize({
    client_id: clientId,
    callback: (response) => accept(response.credential),
    // Back in without a click when one account has signed in here before: a reload, and the
    // renewal before the hour is up.
    auto_select: true,
    cancel_on_tap_outside: false,
    itp_support: true,
    context: "use",
  });
}

function accept(credential) {
  if (!credential) return;
  const claims = readClaims(credential);
  token = credential;
  who = typeof claims.email === "string" ? claims.email : "a Google account";
  try {
    sessionStorage.setItem(KEPT, JSON.stringify({ clientId, credential }));
  } catch {
    // No storage here (a private window, blocked site data): a reload signs in again.
  }
  clearTimeout(renewTimer);
  if (typeof claims.exp === "number") {
    const wait = Math.max(0, claims.exp * 1000 - Date.now() - RENEW_EARLY_MS);
    renewTimer = setTimeout(() => gsi && gsi.prompt(), wait);
  }
  changed("signed-in");
}

function forget() {
  token = null;
  who = null;
  clearTimeout(renewTimer);
}

/** Forgets the token here and in the tab's storage. */
function discard() {
  forget();
  try {
    sessionStorage.removeItem(KEPT);
  } catch {
    // Nothing was kept.
  }
}

/** Takes back the token this tab kept before a reload, if it was given for this client ID
 * and has more than the renewal margin left. The backoffice still checks it. */
function restore() {
  try {
    const kept = JSON.parse(sessionStorage.getItem(KEPT) || "null");
    if (!kept || kept.clientId !== clientId || typeof kept.credential !== "string") return false;
    const exp = readClaims(kept.credential).exp;
    if (typeof exp !== "number" || exp * 1000 - Date.now() <= RENEW_EARLY_MS) {
      sessionStorage.removeItem(KEPT);
      return false;
    }
    accept(kept.credential);
    return true;
  } catch {
    return false;
  }
}

/** A request with `sent` was answered 401. A backoffice not known to want a sign-in is asked
 * again (it may have been restarted with one); a token is dropped only if it is still the
 * one that was refused, not one a renewal brought in since. */
export function refused(sent) {
  if (!clientId) {
    discover();
    return;
  }
  if (token === null || token !== sent) return;
  discard();
  changed("expired");
}

/** Signs out of this page, and keeps Google from signing straight back in. */
export function signOut() {
  if (gsi) gsi.disableAutoSelect();
  discard();
  changed("signed-out");
}

/** Google's sign-in button, drawn into `el`, `width` pixels wide. The page shows its own
 * button and lays this one over it, unseen (app.js `googleButton`): only Google's own button
 * can start the sign-in, and what it looks like is not this page's to choose. */
export function renderButton(el, size, width) {
  if (!gsi) return;
  gsi.renderButton(el, { type: "standard", theme: "outline", size, width, text: "signin_with" });
}

/** The token's claims, read for the address and the expiry only. Never trusted: the
 * backoffice checks the token. */
function readClaims(jwt) {
  try {
    const part = jwt.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = part.padEnd(part.length + ((4 - (part.length % 4)) % 4), "=");
    const bytes = Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    return {};
  }
}

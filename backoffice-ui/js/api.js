// The backoffice API, as this page calls it. Where it is: the address saved on this
// browser from the settings page, else `api` in config.json beside index.html, else this
// page's own origin (`pnpm dev`'s proxy, or a reverse proxy serving the page and `/api`
// under one address).
//
// Every POST and PUT goes as `Content-Type: application/json`, the bodiless ones (halt,
// resume, reload) included: the API refuses a change sent any other way (audit F-02). When
// the backoffice takes a Google sign-in (auth.js), every request carries the ID token as
// `Authorization: Bearer`. Never cookies (`credentials: "omit"`): a browser sends those on
// its own, which is what a page on another site would use.

import { currentToken, refused } from "./auth.js";

const STORAGE_KEY = "backoffice-api";

let base = "";
let configured = "";

/** Reads config.json and this browser's saved address. Called once, before the first view. */
export async function configure() {
  try {
    const res = await fetch("config.json", { cache: "no-store" });
    if (res.ok) configured = normalize((await res.json()).api || "");
  } catch {
    // No config.json, or not JSON: the API is under this page's own origin.
  }
  base = configured;
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved) base = normalize(saved);
  } catch {
    // Storage blocked, or a saved value that no longer parses: config.json's stands.
  }
}

/** `https://pusher.ts.net:8088`, with any path prefix a proxy adds and no trailing slash;
 * empty for this page's own origin. Refuses what is not an http(s) URL. */
export function normalize(value) {
  const text = String(value || "").trim();
  if (!text) return "";
  let url;
  try {
    url = new URL(text);
  } catch {
    throw new Error(`${JSON.stringify(text)} is not an address; write it as https://host:8088`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("the backoffice is reached over http:// or https://");
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new Error("write the backoffice's address alone: scheme, host, port and any path");
  }
  return `${url.origin}${url.pathname}`.replace(/\/+$/, "");
}

/** The address requests go to, for showing: config.json's or the saved one, or this page's. */
export const apiBase = () => base || location.origin;
/** Whether the address in use is one saved on this browser rather than config.json's. */
export const apiOverridden = () => base !== configured;
export const configuredBase = () => configured || location.origin;

/** Saves `value` (an address, or empty to go back to config.json's) on this browser. */
export function setApiBase(value) {
  const next = normalize(value);
  try {
    if (next && next !== configured) localStorage.setItem(STORAGE_KEY, next);
    else localStorage.removeItem(STORAGE_KEY);
  } catch {
    // Not saved, but used for as long as the page is open.
  }
  base = next;
}

/** The websocket address of `path` (the preview), on the same host as the API. */
export function socketUrl(path) {
  const url = new URL(`${base}${path}`, location.href);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  return url.href;
}

/** The subprotocols the preview socket is opened with: when signed in, the token, which a
 * browser cannot put in a websocket's headers, and `backoffice`, which the API answers
 * with. None otherwise, as a backoffice without sign-in expects. */
export function socketProtocols() {
  const token = currentToken();
  return token ? ["backoffice", `bearer.${token}`] : undefined;
}

/** A request the API refused (`status` 4xx, `message` its `{"error"}`), or one that never
 * reached it (`status` 0). */
export class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

/** Why a fetch failed with no answer to read. A browser says only "failed to fetch", for an
 * API that is down and for one that answered without CORS approval alike, so this names
 * the likely causes. */
function unreachable() {
  const page = location.origin;
  const reasons = [
    `Could not reach the backoffice at ${apiBase()}.`,
    "Is it running, and is this the address it is served on?",
  ];
  if (location.protocol === "file:") {
    reasons.push("This page was opened as a file; serve it over http(s) instead (see README.md).");
  } else if (new URL(apiBase()).origin !== page) {
    reasons.push(
      `This page is served from ${page}, another origin than the API's, so the backoffice must ` +
        `list it with --backoffice-cors-origin (BACKOFFICE_CORS_ORIGINS), written exactly so.`,
    );
  }
  reasons.push(
    "Reached by a name rather than an IP address, the backoffice must list that name with " +
      "--backoffice-host. A page served over https can only call a backoffice served over https.",
  );
  return reasons.join(" ");
}

async function request(method, path, body) {
  const init = { method, cache: "no-store", credentials: "omit", headers: {} };
  const token = currentToken();
  if (token) init.headers.Authorization = `Bearer ${token}`;
  if (method === "POST" || method === "PUT") {
    init.headers["Content-Type"] = "application/json";
    if (body !== undefined) init.body = JSON.stringify(body);
  }
  let res;
  try {
    res = await fetch(`${base}${path}`, init);
  } catch {
    throw new ApiError(unreachable(), 0);
  }
  const text = await res.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    // Not JSON: something other than the backoffice answered (a proxy's error page).
  }
  if (!res.ok) {
    const why = data && typeof data.error === "string" ? data.error : text.slice(0, 300);
    if (res.status === 401) refused(token);
    throw new ApiError(why || `${res.status} ${res.statusText}`, res.status);
  }
  if (data === null) {
    throw new ApiError(`${method} ${path} answered something that is not JSON; is ${apiBase()} the backoffice?`, res.status);
  }
  return data;
}

const enc = encodeURIComponent;

export const api = {
  auth: () => request("GET", "/api/auth"),
  pairs: () => request("GET", "/api/pairs"),
  pair: (key) => request("GET", `/api/pairs/${enc(key)}`),
  addPair: (pair) => request("POST", "/api/pairs", pair),
  editPair: (key, pair) => request("PUT", `/api/pairs/${enc(key)}`, pair),
  removePair: (key) => request("DELETE", `/api/pairs/${enc(key)}`),
  halt: (key) => request("POST", `/api/pairs/${enc(key)}/halt`),
  resume: (key) => request("POST", `/api/pairs/${enc(key)}/resume`),
  rearm: (key) => request("POST", `/api/pairs/${enc(key)}/rearm`),
  haltAll: () => request("POST", "/api/halt"),
  reload: () => request("POST", "/api/reload"),
  builders: () => request("GET", "/api/builders"),
  addBuilder: (builder) => request("POST", "/api/builders", builder),
  removeBuilder: (name) => request("DELETE", `/api/builders/${enc(name)}`),
  settings: () => request("GET", "/api/settings"),
  kinds: () => request("GET", "/api/kinds"),
  venues: () => request("GET", "/api/venues"),
  lookup: (token0, token1) =>
    request("GET", `/api/lookup?token0=${enc(token0)}&token1=${enc(token1)}`),
};

// `pnpm dev` serves the page with `/api` proxied to a backoffice, so the page and the API
// share an origin and the backoffice needs no CORS listing. `pnpm build` writes dist/, the
// static files to deploy (README.md).
import { defineConfig } from "vite";

// The backoffice `make quickstart` runs, unless BACKOFFICE_API names another.
const api = process.env.BACKOFFICE_API || "http://127.0.0.1:8088";

export default defineConfig({
  // Relative asset paths, so dist/ works from any directory a server puts it under.
  base: "./",
  server: {
    // Loopback only: this proxy is a way into an API with no login.
    host: "127.0.0.1",
    // Beside the backoffice's 8088, and clear of Vite's 5173, which other projects take, and
    // Grafana's 3000. Strict, so a port in use fails rather than moving.
    port: 8090,
    strictPort: true,
    proxy: {
      "/api": {
        target: api,
        // The preview is a websocket under /api.
        ws: true,
        // Host stays as the browser sent it (127.0.0.1:5173): the backoffice answers to an
        // IP address, and takes a change only when the page's Origin names that same
        // address, which a rewritten Host would no longer match.
        changeOrigin: false,
      },
    },
  },
  preview: {
    host: "127.0.0.1",
    port: 8091,
    strictPort: true,
  },
  build: {
    // app.js awaits config.json at the top level.
    target: "es2022",
  },
});

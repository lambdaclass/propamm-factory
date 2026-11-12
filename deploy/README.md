# Running it in production

One server with Docker, one `docker compose up`: the quote updater, the Postgres it records
into, Prometheus with the shipped alert rules, Alertmanager posting to Slack, and Grafana
with a dashboard of the updater's metrics. Two files to fill, both gitignored: `deploy/.env`
(keys, passwords, addresses) and `deploy/config/config.toml` (the pairs and the builders).
The contracts are not part of it: deploying a PropAMM is a one-off `forge script`, see
[`contracts/`](../contracts/).

## Setup

From a clean state (the first block stops and removes a previous run, including its data
volumes; skip it to keep Prometheus history and the recorder's tables):

```bash
cd deploy
docker compose down --volumes --remove-orphans
rm -f .env config/config.toml alertmanager/slack-webhook

cp .env.example .env
cp config.example.toml config/config.toml
cp alertmanager/slack-webhook.example alertmanager/slack-webhook
$EDITOR .env                        # RPC_URL, RPC_WS_URL, one UPDATER_KEY_* per pair, the passwords, the bind addresses
$EDITOR config/config.toml          # target, builders, pairs
$EDITOR alertmanager/slack-webhook  # the Slack incoming-webhook URL, one line
docker compose build
docker compose run --rm updater --check   # validates everything against the chain, sends nothing
docker compose up -d
docker compose logs -f updater
```

`--check` prints one row per pair: the lane, the stream, whether each key is authorized by
the target and how much ETH it has, and the price it would publish. It exits 1 on anything
the run would refuse, and prints the exact `addUpdater` calls for a key the target does not
know. Run it after every edit to `config.toml` too.

`RPC_WS_URL` is the same node's WebSocket endpoint (`wss://…`). Without it the updater
polls the chain head over `RPC_URL` four times a second and fetches each new block; with
it the node pushes every new block's header the moment it has it, the poll drops to one
liveness check every 3 seconds, and the pairs roll to the next block sooner. There is no
mode to switch: polling covers any spell the subscription is down. `--check` refuses a
URL that is not `ws://` or `wss://` but does not dial it; only a run does, and confirms
it with `[head] subscribed to new heads at <host>`. One that does not answer is logged
once per distinct error while polling carries the head.

## What is where

| Service | Where to reach it | What it holds |
| --- | --- | --- |
| updater | backoffice API at `BACKOFFICE_BIND:8088/api/`, over HTTPS once [set up](#https-for-the-backoffice) | quotes; rewrites `config/config.toml` on every change made through the backoffice |
| grafana | `GRAFANA_BIND:3000`, user `admin` | the "Quote updater" dashboard; Prometheus and the recorder as datasources |
| prometheus | `127.0.0.1:9090` | 90 days of `quote_updater_*` metrics; the rules from [`alerts/`](alerts/) |
| alertmanager | `127.0.0.1:9093` | routes pages and tickets to `#propamm-alerts` |
| postgres | compose network only | the `feed` schema the recorder writes (quotes, mids, vault balances, config history) |

Neither the backoffice nor Grafana has a login worth the name (Grafana's admin password is
in `.env`; the backoffice has none), so publish them on this host's tailnet address and
nothing else: `BACKOFFICE_BIND` and `GRAFANA_BIND` in `.env`. Left at `127.0.0.1` they are
reachable from the host only, or through an ssh tunnel.

## HTTPS for the backoffice

The backoffice is plain HTTP until it is given a certificate. The tailnet already encrypts
the traffic; what HTTPS adds is a front end served over HTTPS being allowed to call it (a
browser refuses an `https://` page's requests to an `http://` API). Tailscale issues the
certificate, for this host's name on the tailnet.

1. In the tailnet's admin console, under DNS, turn on MagicDNS and HTTPS Certificates.
2. On this host, write the certificate and key into `deploy/tls`, under this host's full
   tailnet name (`tailscale status --json | jq -r .Self.DNSName`, without the trailing dot):

   ```bash
   sudo tailscale cert \
     --cert-file deploy/tls/backoffice.crt \
     --key-file deploy/tls/backoffice.key \
     pusher.your-tailnet.ts.net
   ```

3. In `.env`, point the updater at them (paths inside the container, where `deploy/tls` is
   mounted at `/tls`), and keep `BACKOFFICE_BIND` this host's tailnet address, the one that
   name resolves to:

   ```bash
   BACKOFFICE_TLS_CERT=/tls/backoffice.crt
   BACKOFFICE_TLS_KEY=/tls/backoffice.key
   ```

4. `docker compose up -d updater` (not `restart`: `.env` is read when the container is
   created). The log says `backoffice API listening on https://…`, and from then on it is
   HTTPS only:

   ```bash
   curl https://pusher.your-tailnet.ts.net:8088/api/pairs
   ```

Reach it by that name, not by its IP: the certificate names the host, so a client checking
it (every browser, and `curl`) refuses `https://100.x.y.z:8088`. A front end on another
origin still needs that origin listed with `BACKOFFICE_CORS_ORIGINS` in `.env`, as its
`https://` address.

The certificate is short-lived (Let's Encrypt's, 90 days or less). Run the same `tailscale
cert` command from cron or a systemd timer, daily say; it gets a new certificate as the
current one nears its end:

```bash
# /etc/cron.d/backoffice-cert
0 4 * * * root tailscale cert --cert-file /path/to/deploy/tls/backoffice.crt --key-file /path/to/deploy/tls/backoffice.key pusher.your-tailnet.ts.net
```

The updater looks at the two files on every new connection and reads them again when either
changed, so a renewal needs no restart. A connection already open keeps the certificate it
was made with. If the new pair does not load (the moment between the certificate and the key
being written, say), the journal warns once and the old certificate goes on being served
until the files change again. At start, a missing file, an encrypted key or a key that is not
the certificate's refuses the run, naming the file: `docker compose run --rm updater
--check` reports it. `deploy/tls` is gitignored apart from its `.gitkeep`: the key is a
secret. [docs/manual.md](../docs/manual.md), "The backoffice", has the rest.

## Day to day

```bash
docker compose logs -f updater                 # the run
docker compose run --rm updater --check        # after editing config/config.toml by hand
docker compose restart updater                 # then this: the file is read only at start
curl -X POST -H 'Content-Type: application/json' http://<BACKOFFICE_BIND>:8088/api/reload   # re-arm pairs halted by their breaker (https://<name>:8088 with HTTPS)
docker compose up -d updater                   # after editing .env (keys, RPC_WS_URL); restart would not
docker compose pull && docker compose up -d    # newer Prometheus, Alertmanager, Grafana, Postgres
docker compose build updater && docker compose up -d updater   # a new build of the updater
```

The updater reads `config.toml` once, at start. A change made through the backoffice API is
written to it and touches only the pairs and builders that changed, so change those through
the API: a hand edit of them waits for the next start, and the next change made through the
API overwrites it. `target` and `[settings]` are not changed through the API, so they are a
hand edit and a restart; changes made through the API in the meantime keep that edit. `.env`
is read only when the container is created (`docker compose up -d`, not `restart`).
The updater ignores `SIGHUP`, so `docker compose kill -s HUP` no longer reloads anything.
[docs/manual.md](../docs/manual.md) covers the config file, the backoffice API and its
reload, the breaker, the metrics and the recorder.

## Your own pricing models

The image builds `example/`. To run a pricing model of your own, add it to
`example/src/main.rs` (docs/building-your-own.md) and `docker compose build`.

## Notes

- The updater runs as root inside its container so it can rewrite the mounted
  `config/config.toml`; nothing else in the image needs it.
- Postgres keeps its data in the `postgres-data` volume; the updater creates and migrates the
  `feed` schema itself on every connect, so there is nothing to run by hand.
- Alert rules are mounted straight from `deploy/alerts/quote-updater.rules.yml`; a change there is
  live after `docker compose restart prometheus`.

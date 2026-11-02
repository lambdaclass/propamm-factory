# Running inside an enclave

A quote updater normally keeps its keys, its config and its backoffice on the host it runs
on, so whoever gets root on that host has all three. `--enclave` runs the whole updater
inside an enclave instead: a compartment of the host's CPUs and memory that nothing on the
host, root included, can read or change. The host keeps running beside it and does three
things for it: carries its connections, stores what it asks to have stored, and starts it.

What that buys, against someone with root on the host:

- **The keys never leave the enclave.** Every secret is stored on the host encrypted by a
  key service that releases it only to an enclave running your image, as the platform
  proves it. At boot the secrets are decrypted into the enclave, wrapped so they cross the
  host unreadable.
- **The config cannot be read or changed.** The host stores it sealed (AES-256-GCM under a
  key only the enclave has). A changed byte fails the seal, and the run refuses to start.
- **The backoffice cannot be used.** It serves its own HTTPS from inside, with a Google login
  checked inside on every request.
- **The price streams cannot be replaced.** Every connection to a venue, a builder, the RPC
  node or the key service is TLS opened from inside and verified against the certificates
  in the image; the host only copies encrypted bytes. A plain `http://` or `ws://` endpoint
  is refused at startup inside an enclave.

What the host can still do: stop the enclave or cut its connections (quoting stops); restart
it with an older sealed config it copied earlier; read the log lines and metrics; and read or
change what the recorder writes to Postgres, which goes over plain TCP and feeds dashboards,
not quoting.

These hold only on a platform where root on the host really cannot reach into the enclave.
An AWS Nitro enclave is one. A confidential VM is not, for this purpose: it is protected from
the cloud provider, but root inside that VM sees everything in it.

## What differs between platforms

Two things, each chosen by `kind` in the enclave file and each a trait in the library
(`quote-updater/src/enclave/`), so another platform is one more implementation:

| | What it does | Shipped |
|---|---|---|
| `[link]` (`HostLink`) | How the run reaches its host, and whatever the platform needs for the run's other connections | `vsock`: the only channel an AWS Nitro enclave has, with the tunnels that stand in for a network (Linux only) |
| `[release]` (`SecretRelease`) | How the secrets the host hands in are decrypted, by a key service that releases them only to this program | `aws-nitro-kms`: AWS KMS against the Nitro attestation document (the library's `aws-nitro` feature) |

Everything else is the same on any platform: the boot message, the sealed config, the
secret lookup, the backoffice login, the TLS-only rule.

## How a run boots

```
quote-updater --config /run/quote-updater/config.toml --enclave /app/enclave.toml
```

1. The link sets up what it needs and waits for the host's boot helper, which sends one boot
   message: credentials for the key service, every secret as ciphertext, the sealed config,
   and the backoffice certificate.
2. The release decrypts the secrets. They become what every secret lookup reads: a pair's
   `key_env`, a pricer's secret, `ONDO_API_KEY`, `COINGECKO_API_KEY`, `RECORD_DB_URL`, and the
   names the enclave file gives.
3. The config is opened onto `--config`, and the run proceeds as it does anywhere else.
4. From then on the same link carries every log line to the host, the sealed config to the
   host after every save, and the host's reload and shutdown requests to the run.

## The enclave file

Part of the image, so the host cannot change it. Holds no secret.
[`deploy/aws-nitro/enclave.example.toml`](../deploy/aws-nitro/enclave.example.toml) is a
complete one for AWS Nitro.

```toml
[link]
kind = "vsock"
port = 5000

[[link.forward]]               # outbound: a loopback address inside, to a vsock port on the host
listen = "127.0.0.2:443"
cid    = 3
port   = 8001

[[link.accept]]                # inbound: a vsock port, to an address inside
port = 8088
to   = "127.0.0.1:8088"

[release]
kind     = "aws-nitro-kms"
region   = "eu-west-1"
endpoint = "https://kms.eu-west-1.amazonaws.com"

[backoffice]
key_secret = "BACKOFFICE_TLS_KEY"   # the secret holding the certificate's private key
google = { client_id = "….apps.googleusercontent.com", client_secret_secret = "BACKOFFICE_OAUTH_SECRET", redirect_url = "https://backoffice.example.com/auth/callback", allowed_domain = "example.com" }
```

## The boot helper's protocol

The host side is yours to write; this is all it needs, on any platform. Frames in both
directions are a 4-byte big-endian length followed by JSON.

The host sends, once, on connecting:

```json
{
  "kind": "boot",
  "credentials": { "access_key_id": "…", "secret_access_key": "…", "session_token": "…" },
  "secrets": { "CONFIG_SEAL_KEY": "<base64 ciphertext>", "UPDATER_KEY_WETH_USDC": "<…>" },
  "config": "<base64 sealed config>",
  "backoffice_certificate": "-----BEGIN CERTIFICATE-----\n…"
}
```

- `credentials`: what the release's key service is called with, by name. For
  `aws-nitro-kms`, the instance role's temporary credentials from the instance metadata
  service. Used once, at boot.
- `secrets`: each value as the key service encrypted it (`aws kms encrypt`). `CONFIG_SEAL_KEY`
  is required.
- `config`: the last sealed config the enclave sent back. For the very first boot, seal the
  config yourself (below).
- `backoffice_certificate`: the PEM chain, when the enclave file has a `[backoffice]`.

The enclave answers `{"kind":"ready","secrets":[…names…]}`, or
`{"kind":"failed","message":"…"}` and exits. Afterwards it sends
`{"kind":"log","stream":"stdout","line":"…"}` for every operator line and
`{"kind":"config","sealed":"…"}` after every save, which the helper writes over the stored
config. The helper may send `{"kind":"reload"}` (what `systemctl reload` is elsewhere) and
`{"kind":"shutdown"}` (withdraw every quote and exit).

## The first sealed config

The enclave seals every config it saves, but the first one has to be sealed by whoever
creates the sealing key, once, before that key is encrypted for the key service:

```bash
export CONFIG_SEAL_KEY=$(openssl rand -hex 32)
cargo run -p quote-updater --example seal_config -- config.toml > config.sealed
printf '%s' "$CONFIG_SEAL_KEY" | aws kms encrypt --key-id <key> --plaintext fileb:///dev/stdin \
  --query CiphertextBlob --output text > CONFIG_SEAL_KEY.b64
unset CONFIG_SEAL_KEY
```

Put the secrets the config would otherwise read from the environment (the RPC URL, builder
API keys) in the config itself: inside an enclave it is sealed.

## The backoffice

With `[backoffice]` in the enclave file, the backoffice serves HTTPS itself with the
certificate the host hands in and the private key the release decrypts (the two must match,
or it does not start), and asks for a Google login on every page:

- A request without a session is sent to Google; the answer comes back to `redirect_url`
  (`https://<your backoffice name>/auth/callback`, registered on the OAuth client).
- The ID token's signature is checked against Google's published keys, with its audience,
  issuer, expiry and nonce. The account needs a verified email and either Google saying
  `allowed_domain` administers it, or an address in `allowed_accounts`.
- The session is a cookie signed with a key made at startup: a restart logs everyone out.
- Every change made through the page is logged with the account that made it.

The certificate is handed in at boot rather than built into the image so a renewal needs
no new image. That costs nothing in security: only the private key proves the page is
yours, and only the enclave has it.

What does matter is who else can get a certificate for the backoffice's name. Whoever
controls the host controls what answers at that name, and with a valid certificate of their
own they could serve a copy of the page, take a login and replay it. A name whose
certificates the host can obtain by itself (a tailnet name, or a domain validated over HTTP
at that host) allows that. Use a domain whose certificates can only be issued through DNS
validation (a CAA record with `validationmethods=dns-01`), with the DNS credentials kept off
the host, and the DNS record not proxied by a CDN, which would end the TLS before the
enclave.

## AWS Nitro

What `kind = "vsock"` and `kind = "aws-nitro-kms"` need around them.

### The key policy

`kms:Decrypt` for the instance role, only with an attestation document whose measurements
match your image:

```json
{
  "Effect": "Allow",
  "Principal": { "AWS": "arn:aws:iam::<account>:role/<instance role>" },
  "Action": "kms:Decrypt",
  "Resource": "*",
  "Condition": { "StringEqualsIgnoreCase": { "kms:RecipientAttestation:PCR8": "<hash>" } }
}
```

PCR8 is the hash of the certificate the image is signed with (`nitro-cli build-enclave
--signing-certificate`), so every image signed with it gets the keys and a release needs no
policy change; whoever holds that certificate's key decides what runs. PCR0 pins one exact
image instead, so every release needs the policy updated to its new hash.

### The tunnels

Each `[[link.forward]]` stands in for one host the updater connects to. The image's hosts
file points that host's name at the loopback address the forward listens on, so the updater
dials the name as usual and TLS is checked against the name, end to end through the tunnel.
On the host, one `vsock-proxy` per destination, each allowed in
`/etc/nitro_enclaves/vsock-proxy.yaml`:

```
vsock-proxy 8001 kms.eu-west-1.amazonaws.com 443
vsock-proxy 8002 stream.binance.com 9443
```

### The image

[`deploy/aws-nitro/Dockerfile`](../deploy/aws-nitro/Dockerfile) builds `example/` with the
`aws-nitro` feature and packages it with the enclave file and the hosts file:

```bash
docker build -f deploy/aws-nitro/Dockerfile -t quote-updater-enclave .
nitro-cli build-enclave --docker-uri quote-updater-enclave:latest --output-file quote-updater.eif \
  --signing-certificate cert.pem --private-key key.pem
nitro-cli run-enclave --eif-path quote-updater.eif --cpu-count 2 --memory 2048 --enclave-cid 16
```

`build-enclave` prints the measurements; PCR8 is what the key policy pins. Then the host's
boot helper connects to `16:<port>`.

## Another platform

Implement `SecretRelease` (the platform's attested key release) and, if its connection to the
host is not a vsock, `HostLink`; add a `kind` for each in `enclave/mod.rs`. The boot message,
the sealing, the secrets, the backoffice and the TLS rule need no change.

Self-signed certificates and keys for the backoffice's HTTPS tests (`src/tls.rs`,
`src/backoffice.rs`, `src/pusher.rs`). TEST ONLY: they were generated for this directory,
protect nothing, and must never be used to serve anything.

| File | What it is |
|---|---|
| `a.crt`, `a.key` | EC P-256, the key in SEC1 (`BEGIN EC PRIVATE KEY`), the form `tailscale cert` writes |
| `b.crt`, `b.key` | RSA 2048, the key in PKCS#1 (`BEGIN RSA PRIVATE KEY`) |
| `b.pk8.key` | `b.key` in PKCS#8 (`BEGIN PRIVATE KEY`) |
| `a.enc.key` | `a.key`, encrypted (`BEGIN ENCRYPTED PRIVATE KEY`), which the pusher refuses |

Both certificates name `localhost` and `127.0.0.1` and are valid for 100 years; the tests
accept any certificate and compare the one presented with these files, so no trust store
is involved.

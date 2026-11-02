# quote-signer

A separate signing process for a quote updater. The updater keeps building every update's
transaction exactly as before; instead of holding the key, it sends the unsigned fields to
this process over a socket and gets the signature back. This process holds the keys, and
before signing anything it decodes the transaction and judges it against a policy: the
registry it may call, the chain, the gas, the lanes each key may quote, and how far a
published mid may sit from a reference price the process reads for itself.

So a host that can reach the signer can get updates signed, within the policy, and nothing
else: a key is never in the updater's memory, never on its disk, never in its environment.

Two ways to run it, same program:

- **On a plain host**, as a second process beside the updater, listening on a Unix socket
  and reading its keys from a file only it can read. The updater process no longer holds
  keys; root still can.
- **In an AWS Nitro enclave** (built with `--features nitro`), where the keys are stored as
  KMS ciphertext and KMS decrypts them only for this program's attested image. The
  plaintext keys exist in the enclave's memory and nowhere else; not even root on the
  instance can read them. See [Running in a Nitro enclave](#running-in-a-nitro-enclave).

Everything between those two, the policy, the signing, the wire protocol, is identical.
Where the keys come from is one trait (`keys::KeyRelease`) with one implementation each.

## The updater's side

A pair's key variable (`key_env` in its config) holds either the key, as it always has, or
the signer's endpoint and the key's address:

```
UPDATER_KEY_WETH_USDC=unix:///run/quote-signer.sock?address=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
UPDATER_KEY_USDC_USDT=vsock://16:5000?address=0x70997970C51812dc3A010C7d01b50e0d17dc79C8
```

Nothing else in the updater's config changes. `--check` connects to the signer and fails
the row if it is unreachable or holds no key for that address. At run time each pair keeps
one connection open; a signature takes a socket round trip plus the signature itself, which
`quote_updater_sign_duration_seconds` measures and `PusherSigningSlow` pages on. A refusal
or an unreachable signer counts in `quote_updater_sign_errors_total`, the update is not
published that tick, and the reason is in the updater's log.

The address is in the variable because the updater needs it before it ever connects: to
check the key is authorized on chain and funded, and to report it.

## Running on a plain host

A config file:

```toml
[listen]
unix = "/run/quote-signer/quote-signer.sock"

[keys]
file = "/etc/quote-signer/keys.txt"      # one hex key per line, readable by this process only

[policy]
registry      = "0x…"                    # the only contract a signed transaction may call
chain_id      = 1
max_gas_limit = 120000
max_fee_per_gas_gwei = 500               # optional

[[policy.keys]]
address = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
target  = "0x…"                          # the PropAMM this key updates
lanes   = ["0x…"]                        # the lanes it may quote (the updater's --check prints them)
reference = { symbol = "ETHUSDC", inverted = true, price_decimals = 18, max_distance = "0.02", max_age_secs = 30 }

[[policy.keys]]
address = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
target  = "0x…"
lanes   = ["0x…"]
```

Then:

```bash
quote-signer --config /etc/quote-signer/config.toml
```

It logs the addresses it signs for and listens. The socket's permissions are the access
control: put it in a directory only the updater's user can enter.

[`config.example.toml`](config.example.toml) documents every key.

### The policy

Every request is judged in this order, and the first failure is the refusal the updater
logs:

1. The key is one the policy names.
2. `chain_id` matches.
3. The transaction calls `registry` and carries no value.
4. The gas limit is at most `max_gas_limit`; the fee cap at most `max_fee_per_gas_gwei`
   when set; the priority fee at most the fee cap.
5. The calldata is `updateState(address,uint256,uint32,uint256[])` with two or three values.
6. Its `target` is this key's, and its lane is one of this key's.
7. With a `reference` on the key: the signer has read that symbol within `max_age_secs`,
   and the published mid (scaled by `price_decimals`, the reciprocal of the venue's price
   when `inverted`) is within `max_distance` of it. No reading, or a stale one, is a refusal:
   the check fails closed.

A key without a `reference` gets checks 1 to 6 only. That is still worth having (nothing
but an update to the right contract for the right lane can be signed), but it does not
bound the price, so give every key a reference unless its lane has no venue to read.

The reference comes from `[reference]`: a venue's book ticker, polled by this process at
`poll_ms`, Binance's `GET /api/v3/ticker/bookTicker` shape by default. `max_distance` is
a fraction of the price: `"0.02"` is 2%. Set it to a few times the widest spread the pair
publishes, and well inside the move an attacker could profit from; a mid that far from the
venue is one no honest pricer would publish.

### What it protects, and what it does not

With the keys in this process instead of the updater:

- The updater's binary, config, environment, core dumps and logs never hold a key.
- Whoever can reach the socket can get updates signed, within the policy, for as long as
  they can reach it. They cannot take the key.
- On a plain host, root can still read this process's memory or the key file. That is what
  the enclave is for.

The policy bounds what a compromised updater can publish; it does not make a compromised
updater harmless. An attacker who controls the updater can still stop quoting, or quote at
the edge of `max_distance` in the direction they want. Keep the band tight.

## Running in a Nitro enclave

Build with `--features nitro`. The one difference is `[keys]`:

```toml
[listen]
vsock_port = 5000

[keys]
nitro = { boot_port = 5001, region = "eu-west-1", kms_endpoint = "https://kms.eu-west-1.amazonaws.com" }

[[forward]]                 # the enclave has no network: loopback ports tunnelled to the host
listen = "127.0.0.1:443"
cid = 3
port = 8001

[reference]
base_url = "https://api.binance.com"
```

### How the keys get in

1. **Once, anywhere with the AWS CLI:** encrypt each key with the KMS key.

   ```bash
   aws kms encrypt --key-id <key id> --plaintext fileb://<(printf '%s' "$UPDATER_KEY_WETH_USDC") \
     --query CiphertextBlob --output text > UPDATER_KEY_WETH_USDC.b64
   ```

   The plaintext is the key's hex, exactly what the variable used to hold. The blobs are
   ciphertext under a key that only the attested enclave can use; they can live in a
   repository or a deploy directory.

2. **The KMS key policy** allows `kms:Decrypt` to the instance's role only when the request
   carries an attestation document whose PCR matches the enclave image, in the form AWS
   documents for Nitro Enclaves:

   ```json
   {
     "Effect": "Allow",
     "Principal": { "AWS": "arn:aws:iam::<account>:role/<instance role>" },
     "Action": "kms:Decrypt",
     "Resource": "*",
     "Condition": { "StringEqualsIgnoreCase": { "kms:RecipientAttestation:PCR8": "<hash>" } }
   }
   ```

   PCR8 is the hash of the certificate the image is signed with, so a rebuilt image signed
   with the same certificate keeps the policy; PCR0 would pin one exact build. Keep the
   signing certificate's key out of the instance.

3. **At boot**, after `nitro-cli run-enclave`, a helper on the host connects to the
   enclave's `boot_port` over vsock and sends one frame (4-byte big-endian length, then
   JSON) with the instance role's temporary credentials and the blobs:

   ```json
   {
     "access_key_id": "…", "secret_access_key": "…", "session_token": "…",
     "ciphertexts": ["<base64 blob>", "<base64 blob>"]
   }
   ```

   The enclave generates an RSA key, gets an attestation document from the Nitro Security
   Module carrying its public half, calls KMS `Decrypt` with the document for each blob,
   opens the CMS envelope KMS answers with (RSA-OAEP-SHA256 key transport, AES-256-CBC
   content), and answers the helper with one frame:

   ```json
   { "kind": "loaded", "addresses": ["0x…", "0x…"] }
   ```

   or `{ "kind": "failed", "message": "…" }`, after which it exits. That reply is the
   host's only view of what happened inside a production enclave (one with no console), so
   the helper should log it and the host's monitoring should expect it. The credentials
   are used once, for the `Decrypt` calls at boot, and dropped.

### Reaching KMS and the venue from inside

An enclave has no network interface. Each `[[forward]]` entry listens on a loopback port
inside and pipes every connection to a vsock port on the host (`cid = 3`), where the AWS
`vsock-proxy` dials the real host. TLS runs end to end through the tunnel; the enclave's
`/etc/hosts` points the service's name at the loopback address, so the AWS SDK and the
reference poller see a normal HTTPS endpoint. The image's entrypoint brings `lo` up and
appends the `hosts` file you build in; the host side needs one `vsock-proxy` per
destination, for example:

```
vsock-proxy 8001 kms.eu-west-1.amazonaws.com 443 &
vsock-proxy 8002 api.binance.com 443 &
```

with both hosts in the proxy's allowlist (`/etc/nitro_enclaves/vsock-proxy.yaml`).

### Building the image

[`Dockerfile`](Dockerfile) builds the binary with the `nitro` feature and packages it with
the config and hosts file from a directory you pass as the build context's `enclave/`.
Then:

```bash
docker build -f quote-signer/Dockerfile -t quote-signer-enclave .
nitro-cli build-enclave --docker-uri quote-signer-enclave:latest --output-file quote-signer.eif \
  --signing-certificate cert.pem --private-key key.pem
nitro-cli run-enclave --eif-path quote-signer.eif --cpu-count 2 --memory 1024 --enclave-cid 16
```

`build-enclave` prints the measurements; PCR8 is what the key policy pins. The updater
on the host then points each pair at `vsock://16:5000?address=0x…`.

A deploy of the updater never touches the enclave; a deploy of the enclave is a new image,
a restart of the enclave (during which the updater cannot sign and its quotes lapse, as
they would across a restart of the updater itself), and the same boot sequence.

## The protocol

One request, one response, framed as a 4-byte big-endian length and JSON, on a Unix socket
or a vsock. The request carries the unsigned EIP-1559 fields (`chain_id`, `nonce`, the
two fees, `gas_limit`, `to`, `value`, `data` as hex); the response is the signature as
`r`, `s`, `y_parity`, or a refusal with its reason. The signer rebuilds the signing payload
from the fields it judged, so it can only sign what it saw; the updater recovers the
signer's address from the signature before using it, so it only publishes what the right
key signed. `protocol.rs` is the definition, and `quote-updater` depends on this crate for
it, so the two sides are one source.

## Building and testing

Part of the workspace: `cargo test -p quote-signer`, and `--features nitro` for the key
release's own tests, which run anywhere (the envelope test builds the same CMS structure
KMS returns and opens it; nothing needs an enclave). The Nitro attestation and KMS calls
themselves can only be exercised in an enclave.

# Build inputs for the enclave image

`Dockerfile` copies two files from here (or from the directory `BUILD_DIR` names):

- `config.toml`: the signer's config for the enclave: `[listen] vsock_port`, `[keys] nitro`,
  the `[policy]`, and one `[[forward]]` per service reached from inside. Start from
  `../config.example.toml`.
- `hosts`: one `/etc/hosts` line per forwarded service, pointing its name at the loopback
  port the matching `[[forward]]` listens on:

  ```
  127.0.0.1 kms.eu-west-1.amazonaws.com
  127.0.0.2 api.binance.com
  ```

  Two services on port 443 take two loopback addresses, as above, with a `[[forward]]`
  listening on each.

Neither file holds a secret, so they can be committed to the deploy repository that
builds the image.

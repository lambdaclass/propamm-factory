# my-propamm

Someone's own PropAMM quote updater, built on the
[`quote-updater`](../quote-updater) library. This is the "small amount of code" a
team writes: one file, `src/main.rs`, about 300 lines including comments, most of them
optional.

What it adds, one per extension point the library offers:

- `inventory_skew`, a pricing model: fixed half-spread, mid pushed away from the token the
  vault holds too much of, so fills rebalance it. Reads the vault through the library.
- `venue_spread`, a market guard: stops the pair when the exchanges behind the price disagree.
- `share_cap`, a quote guard: withdraws the quote while the vault is lopsided, halts the pair
  if the pricer reports an impossible share.
- `block_log`, an observer: one log line per block and per lifecycle event.

`main()` at the bottom registers the four and calls `run_from_env()`. Everything else is the
library's. The smallest possible binary is 30 lines; see the library README.

## Run it against a local chain with your own PropAMM

From the repo root:

```bash
make quickstart                       # deploys the contracts on anvil, builds this, quotes
```

The quickstart uses `config.local.toml`: `--mode node`, which sends `updateState`
transactions straight to the chain, since a local chain has no block builders.

## Run it against fake builders and a fake Binance

`config.mocks.toml` points at the library's Python mocks (two builders, Binance, a chain that
mines every 3s). Terminal 1, from the repo root: `make mocks`. Terminal 2:

```bash
export UPDATER_KEY_WETH_USDC=0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a
export UPDATER_KEY_USDC_USDT=0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6
cargo run -- --config config.mocks.toml --check
cargo run -- --config config.mocks.toml
```

Watch `curl -s 127.0.0.1:9464/metrics | grep -E 'diagnostic|guards|observer'` while it runs.

## Run it for real

`config.toml` is the production shape: a real RPC, real builders and their API keys, your
PropAMM's address, one block per pair with its signing key's env var. Validate with
`--check`, then run without it.

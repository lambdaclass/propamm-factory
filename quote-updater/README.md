# quote-updater

The off-chain half of a PropAMM: a Rust
library that streams prices, runs your pricing model on every tick, signs one priority update
per pair per block, sends it to the block builders, and checks that it landed. You write the
pricing model and a `main`; the library does the rest.

```
your binary (main.rs)                    this library
───────────────────────                  ──────────────────────────────────────────────
register your pricing model      ──►     price feeds (Binance, Kraken, Coinbase, ...)
register guards (optional)       ──►     per-block quote loop, signing, builders
register an observer (optional)  ──►     landing checks, metrics, config reload, --check
call run_from_env()                      backoffice web page, circuit breaker
```

## Five minutes to a running quote updater

A binary of your own is a crate that depends on this one. The smallest complete one is
[`examples/custom_pricer.rs`](examples/custom_pricer.rs), 30 lines:

```toml
# Cargo.toml
[dependencies]
quote-updater = { git = "https://github.com/lambdaclass/propamm-factory", rev = "<commit>" }
serde = { version = "1", features = ["derive"] }
```

```rust
// src/main.rs
use quote_updater::prelude::*;

#[derive(Clone, serde::Deserialize)]
struct Skewed { half_spread: f64, skew: f64 }   // the fields of your [pairs.pricing] block

struct SkewedPricer { cfg: Skewed }

impl Pricer for SkewedPricer {
    // Every tick: the market as a person reads it (USDC per WETH) in, a mid and a
    // half-spread out. The library converts both to what the contract stores.
    fn price(&mut self, tick: &TickCtx, _out: &mut Diagnostics) -> Result<PricerOutput, Refusal> {
        let market = tick.market()?;
        Ok(PricerOutput::new(
            market.scaled_fraction(self.cfg.half_spread)?,   // 0.0005 = 5 bp
            market.shift(self.cfg.skew)?,                    // +0.01 = a mid 1% below market
        ))
    }
}

fn main() -> std::process::ExitCode {
    Updater::builder()
        .pricer_fn("skewed", |cfg: Skewed, _ctx: &mut BuildCtx| Ok(SkewedPricer { cfg }))
        .run_from_env()
}
```

```toml
# config.toml
target = "0x<your PropAMM>"              # the contract your updates are for

[settings]
rpc_url = "https://<your rpc>"

[[builder]]
name     = "titan-eu"
endpoint = "wss://eu.rpc.titanbuilder.xyz/ws/sendquoteupdate"
api_key  = "<your maker key>"

[[pairs]]
tokens  = ["0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"]
symbol  = "ETHUSDC"                      # the market to follow
key_env = "UPDATER_KEY_WETH_USDC"        # env var holding this pair's signing key

[pairs.pricing]
kind        = "skewed"                   # the name main.rs registered
half_spread = 0.0005
skew        = 0.0
```

```bash
export UPDATER_KEY_WETH_USDC=0x<key the PropAMM authorized as an updater>
cargo run -- --config config.toml --check     # validates everything, prints what it would quote, sends nothing
cargo run -- --config config.toml             # quotes every block
```

A fuller example with a pricer that reads the vault, two guards and an observer is
[`example/`](../example).

## What you can plug in

- **A pricing model** (`Pricer`): any math over the market price, your vault balances
  (`ctx.inventory()`), chain reads (`ctx.chain()`), the price history, HTTP. The library
  ships three, registered in `main` exactly like yours: `fixed`, `feed`, `volatile` (a
  volatility-scaled spread with an inventory tilt).
- **Price sources**: one venue or several averaged by weight, per pair, in the config.
- **Guards**: code that stops a pair. A market guard judges every incoming price, a quote
  guard judges every quote you are about to publish. Built-in: the deviation breaker.
- **Observers**: code that is told what happened (lane started, block quoted, pair halted)
  and decides nothing.

[docs/building-your-own.md](../docs/building-your-own.md) is the full guide to all four.

## What the library does for you

Config file with validation and hot reload, `--check` dry runs, the feeds, signing and
sending to builders every block, landing checks, Prometheus metrics, a backoffice web page
to edit pairs, a circuit breaker per pair, and a recorder that writes every quote to
Postgres if you want one. [docs/manual.md](../docs/manual.md) is the operator's manual for all
of it.

Rust 1.98.1, pinned in the repo's `rust-toolchain.toml`. `make lint`, `make cargo-test`, `make e2e` and `make downstream` from the repo root are what CI runs.

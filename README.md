# propamm-factory

Everything needed to run your own PropAMM: the contracts, the off-chain quote updater that
sets its price every block, and an example of the small program you write on top.

A PropAMM is a market maker that fills swaps from a vault at a price you choose, with no
liquidity pool. Every block you publish a mid and a spread through Flashbots' priority
update registry; the block builder places that update at the top of the block, before any
trade that reads it; the contract fills trades at that price out of your vault. A price is
valid only in the block it was written for, so you are never filled on a stale quote.

```
contracts/        PropAMM and PropAMMFactory (Foundry). One transaction creates your instance.
quote-updater/    the Rust library: price feeds, your pricing model every tick, signing,
                  sending to builders, landing checks, metrics, config reload, a backoffice page
example/          a complete quote updater built on the library, in one file
e2e/              Python mocks of chain, builders and Binance, and the end-to-end run
docs/             building-your-own.md (pricing models, guards, observers), manual.md (operating it)
alerts/           Prometheus alert rules for the metrics the updater exposes
```

## The whole thing on a laptop

```bash
QUICKSTART_SECONDS=40 ./quickstart.sh
```

Starts a local chain, deploys the registry, the factory and a PropAMM with a USDC/USDT pair,
builds `example/` and quotes that pair from Binance's live book for 40 seconds, then shows
the chain answering `isActive` and `quote` at the published price. Without the variable it
keeps quoting until ctrl-c. Needs [Foundry](https://book.getfoundry.sh/), Rust via rustup
(the toolchain is pinned in `rust-toolchain.toml`), python3, and internet for the price
stream.

## What you write

A pricing model is a struct with one method, registered under a name in `main`:

```rust
use quote_updater::prelude::*;

#[derive(Clone, serde::Deserialize)]
struct Skewed { half_spread: f64, skew: f64 }   // the fields of your [pairs.pricing] block

struct SkewedPricer { cfg: Skewed }

impl Pricer for SkewedPricer {
    // Every tick: the market as a person reads it (USDC per WETH) in, a mid and a
    // half-spread out. The library converts both to what the contract stores.
    fn price(&mut self, tick: &TickCtx, _: &mut Diagnostics) -> Result<PricerOutput, Refusal> {
        let market = tick.market()?;
        Ok(PricerOutput::new(
            market.scaled_fraction(self.cfg.half_spread)?,   // 0.0005 = 5 bp
            market.shift(self.cfg.skew)?,                    // +0.01 = a mid 1% below market
        ))
    }
}

fn main() -> std::process::ExitCode {
    Updater::builder()
        .pricer_fn("skewed", |cfg: Skewed, _: &mut BuildCtx| Ok(SkewedPricer { cfg }))
        .run_from_env()
}
```

That is [`quote-updater/examples/custom_pricer.rs`](quote-updater/examples/custom_pricer.rs),
complete. A config file names your PropAMM, your RPC, your builders and one block per pair
with its tokens, the market to follow, the env var holding its signing key, and
`kind = "skewed"`. `--check` validates everything and prints what it would quote without
sending anything. [`quote-updater/README.md`](quote-updater/README.md) is the five-minute
version; [`docs/building-your-own.md`](docs/building-your-own.md) covers pricing models that
read the vault or the chain, guards (code that stops a pair) and observers (code that is told
what happened); [`example/`](example/README.md) uses all of them.

## Contracts

`PropAMM` fills swaps from a vault at the price read from the registry; `PropAMMFactory`
creates instances with `createPropAMM(owner, oracle, updaters, pairs)`, each pair naming the
vault it fills from and the keys allowed to set its price. [`contracts/`](contracts/) has the
sources and tests.

```bash
make local          # anvil with the registry, the factory and one PropAMM deployed
make price-service  # keep its price fresh with the library's built-in model, no code of yours
make swap           # trade against it
make local-down
```

## Developing

```bash
make test           # forge test
make lint           # cargo fmt and clippy, as CI runs them
make cargo-test     # the library's tests
make e2e            # the library against the Python mocks (~30s)
make downstream     # a crate outside the workspace built against the library
```

MIT licensed.

# The pieces

## The contracts

`PropAMMFactory` creates PropAMM instances. One call does it:

```solidity
createPropAMM(owner, oracle, updaters, pairs)
```

`owner` manages the instance afterwards, `oracle` is the priority update registry it reads
prices from, `updaters` are the addresses allowed to publish prices, and `pairs` is a list of
`(token0, token1, vault)`: the two tokens and the wallet that holds the inventory for that
pair. Each pair can have its own vault.

The factory has an owner of its own, set when it is deployed, whose one power is
`disableCreation`: it stops `createPropAMM` for good and emits `CreationDisabled`. Nothing turns
creation back on. Instances already created keep working, and the factory's owner has no say
over them.

`PropAMM` is the instance. The owner can add and remove pairs (`addPair`, `setPairVault`),
add and remove updaters (`addUpdater`, `removeUpdater`, and `removeUpdaterFrom` for a registry
the instance has moved away from), point it at another registry (`setOracle`) and pause it. Traders call `swap`;
anyone can call `quote` and `isActive` to see what a trade would get.

Instances also implement `IPropAMMFillable`, advertised through ERC-165, which
`PropAMMRouter`'s split routing (`swapSplitV1`) prices a venue with in one call:
`quoteFillable(tokenIn, tokenOut, amountIn)` answers with how much of the order the pair's vault
can fill (the lesser of its output-token balance and its allowance to the instance) and what that
part pays, so an order larger than the vault still routes its fillable part here. The router
reads every capacity before any leg fills, so two instances it lists must not fill the same
output token from the same vault: when one instance replaces another, take the old one off the
router's venue list first.

Sources and tests are in [`contracts/`](../contracts/). `make test` runs the tests.

## The quote updater

A Rust program built on the `quote-updater` library. The library does the heavy lifting:
connecting to exchange price feeds, signing the update every block, sending it to the
builders, checking it landed, exposing metrics, applying config changes while running, and
serving the backoffice API. What you write is the part that decides the price.

The library ships three pricing models you can use as they are:

- `fixed`: the same mid and spread, while the pair's market sits inside that spread; it stops
  quoting when the market leaves it (see [pricing.md](pricing.md)). For a pair whose price
  should not move. On a stablecoin pair, `feed` with a band is the better default.
- `feed`: the exchange mid as it is, with the exchange's spread or one you set.
- `volatile`: a spread that widens when the price is moving and a mid that tilts to rebalance
  your vault. This is what you want for something like WETH/USDC.

You can also write your own. A pricing model is one Rust struct with one method that gets
the market price in and returns a mid and a spread. The smallest complete program is about
30 lines, in [`quote-updater/examples/custom_pricer.rs`](../quote-updater/examples/custom_pricer.rs);
[`example/`](../example/) is a fuller one that reads the vault and adds guards and logging.
[`building-your-own.md`](building-your-own.md) explains how.

Everything else is configuration: a TOML file with your PropAMM's address, your RPC, your
builders, and one block per pair saying which tokens, which exchanges to follow, which
pricing model with which settings, and the name of the environment variable holding that
pair's signing key. `--check` validates all of it against the chain and prints what it would
publish, without sending anything. [`manual.md`](manual.md) is the operating manual.

**The backoffice** is a JSON API the updater serves under `/api`. Through it you add and
remove pairs, pick the exchanges a pair follows and their weights, change a pair's pricing
settings, add builders, and halt or resume a pair. It serves no pages: a front end, such as
the one in [`backoffice-ui/`](../backoffice-ui/README.md), or `curl`, talks to it. Every
change is written to the config file and applied without a restart. You put it on a private
address (your tailnet), and can also require a Google sign-in from an allowed Workspace
domain or address.

## Monitoring

The updater exposes Prometheus metrics for everything it does: whether each pair is quoting,
whether updates are landing, the price feeds, the builders, the signer's ETH balance.
[`deploy/alerts/`](../deploy/alerts/) has the alert rules for them. [`deploy/`](../deploy/)
runs Prometheus with those rules, Alertmanager posting them to Slack, Grafana with a
dashboard of the updater, and a Postgres database where the updater records every quote it
published and why, so you can look at it later.

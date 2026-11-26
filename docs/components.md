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

A price is good for one block. The instance asks the registry for the update stamped with the
current block's timestamp and checks the stamp on the answer, so a registry that keeps no such
window and hands back an older update is refused rather than priced from. The check is only as
good as the stamp: a registry that misreports its timestamps is believed, as the registry is for
the price itself. One block means one timestamp: on a chain whose blocks can share a timestamp
an update is good for all of them, and before deploying on one the updater should publish the
block number in an extra slot for the instance to require. The registry keeps timestamps in 32
bits, which run out on 7 February 2106; this implementation is not meant to quote past that date.

`swap` reverts rather than settle a trade that moves nothing or loses its output: an `amountIn`
of zero, an input worth less than one wei of the output token, and a `recipient` that is the zero
address or the pair's own vault. The instance itself is a valid recipient: a router taking two
hops on one instance names it for the first hop, and the output is then in place as the second
hop's input. `swap` cannot be re-entered from a token's transfer; one swap after another in the
same transaction is fine.

`isActive` answers true when `quote` has what it needs to price the pair: the instance is not
paused, the pair is listed, the registry holds this block's update for it with a `delta` below
one and a `mid` that is not zero, and the vault holds some of the output token. It never reverts
and is not told a size, so a quote for a real amount can still fail on the vault's balance, and a
swap on its allowance.

An instance logs the configuration it starts with: `initialize` emits `OracleChanged`, an
`UpdaterAuthorized` per updater and a `PairAdded` per pair, the events later changes emit. The
exception is an instance created by an earlier implementation and upgraded to this one, which
never logged its oracle or its first updaters; for it the registry's own log is the record.
`setOracle` moves no updaters, which is why each updater event names the registry it was made
on. The factory's `PropAMMCreated` names the instance, its creator, its owner, the oracle and the
updaters. `setPairVault` to the vault a pair already has reverts, and so does `setOracle` to
the registry the instance already reads, like `removePair` of a pair that is not listed: no event
reports a change that did not happen.

Instances also implement `IPropAMMFillable`, advertised through ERC-165, which
`PropAMMRouter`'s split routing (`swapSplitV1`) prices a venue with in one call:
`quoteFillable(tokenIn, tokenOut, amountIn)` answers with how much of the order the pair's vault
can fill (the lesser of its output-token balance and its allowance to the instance) and what that
part pays, so an order larger than the vault still routes its fillable part here. The router
reads every capacity before any leg fills, so two instances it lists must not fill the same
output token from the same vault: when one instance replaces another, take the old one off the
router's venue list first.

A fill pays the spread the update publishes plus a charge for its size. By default that is a
fixed impact, 1 bp for a fill worth the whole vault and in proportion below it. An update can
carry a size table in its place (`SizeTable.sol`): rows of "up to this share of the vault,
this much more", of which a fill pays the average over the rows it spans. A block's fills in
one direction are counted together, in `fills`, so each continues the table from where the
last one stopped and a split order pays what the whole would. See "Size charges" in
[the manual](manual.md).

An update can also carry a retail delta: a smaller spread, paid in place of the published one
by a swap that carries an attestation from one of the instance's retail signers
(`addRetailSigner`, `removeRetailSigner`), the keys of venues trusted to say which flow is
retail. Such a swap goes through `swapRetail`, and `quoteRetail` and `quoteFillableRetail`
answer what it would get (`IPropAMMRetail`); `swap` and `quote` keep the published spread. An
attestation names the pair, the direction, the most it may sell, an expiry, a nonce good once
per signer, and an account that has to take part in the swap. See "Retail flow" in
[the manual](manual.md).

Sources and tests are in [`contracts/`](../contracts/). `make test` runs the tests, and
`make mutants` checks the tests themselves: it plants one bug at a time in the contracts and
fails if any of them goes unnoticed.

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
settings and its guards, add builders, and halt or resume a pair. It serves no pages: a
front end, such as the one in [`backoffice-ui/`](../backoffice-ui/README.md), or `curl`,
talks to it. Every change is written to the config file and applied without a restart. You
put it on a private address (your tailnet), and can also require a Google sign-in from an
allowed Workspace domain or address.

## Monitoring

The updater exposes Prometheus metrics for everything it does: whether each pair is quoting,
whether updates are landing, the price feeds, the builders, the signer's ETH balance.
[`deploy/alerts/`](../deploy/alerts/) has the alert rules for them. [`deploy/`](../deploy/)
runs Prometheus with those rules, Alertmanager posting them to Slack, Grafana with a
dashboard of the updater, and a Postgres database where the updater records every quote it
published and why, so you can look at it later.

# Capitán Monasterio — a real malicious maker, on ElZorro's own contract

(named after the villain of season 1 of Disney's classic Zorro series: the one who moves the price against the Zorro.)

**What this is:** a Foundry security PoC. Not a new contract and not a theoretical attack model —
it runs the repo's own `PropAMM.sol` (the same contract this factory deploys for a live maker),
against an oracle mock that enforces the same authorization a real `IPrioUpdateRegistry` lane
requires (`addUpdater`/`isUpdater`), unlike the repo's shared `MockPUR` test double, which leaves
`setState` open to any caller by design (that one is fine for the repo's own pricing tests, which
aren't testing authorization). The "malicious" piece here is not custom attacker code: it's the
same `updateState` call an honest updater service makes, under someone else's control.

**File:** `contracts/test/CapitanMonasterioQuoteAndPull.t.sol`
**Run** (no RPC, no mainnet fork, fully local — 6/6 passing):
```
cd contracts
forge test --match-path 'test/CapitanMonasterioQuoteAndPull.t.sol' -vv
```

## Revision history

v1 of this PoC used the repo's shared `MockPUR`, whose `setState` has no access control, so
`vm.prank(updater)` was decorative — every test passed regardless of `msg.sender`. It also framed
ordinary quote-and-pull under an honest updater (price changes between a taker's `quote()` read
and its `swap()` landing, bounded by `minAmountOut`) as if it were the compromise scenario, and
didn't model the actual high-severity case. This version:
- adds `MockPURAuthenticated` (a dedicated test mock, only used here — the shared `MockPUR` is
  untouched) so the updater's authorization is real, not decorative;
- adds a test that proves an unregistered address cannot write a price at all;
- adds the scenario a compromised key genuinely enables (below);
- keeps the honest-price-change tests, relabeled as controls, not the vulnerability.

## The actual finding: a compromised updater key can drain the vault in one transaction

`_pricing` only checks `mid != 0` (`PropAMM.sol:298`) — nothing compares the oracle's `mid`
against any external reference. An address holding a valid, authorized updater key (compromised
laptop, leaked CI secret, whatever the compromise vector) can write any `mid` it wants, then swap
against the vault in the same transaction at that price.

`test_compromisedUpdaterKey_drainsVaultWithAdverseMid` measures exactly this: vault funded with
10,000 `tokenOut` at an honest mid of 2,500, the authorized key writes a mid 99% below market,
and the attacker calls `quoteFillable` (the contract's own "most this pair can pay in one fill"
function — used here to find the attacker's input size, rather than guessing one) and swaps for
it. Result: **9,999.999999999999979976 tokenOut drained, 20,024 wei left in the vault** — the
vault's entire balance, in one transaction.

## What is NOT the vulnerability (kept as controls)

An honest updater changing the price between a taker's `quote()` read and its `swap()` landing is
normal operation, not a compromise — every maker does this on its ordinary update schedule.
`swap()` re-quotes fresh at execution (`PropAMM.sol:168`), so:
- tight `minAmountOut` (pinned to the price the taker saw): the fresh, worse quote fails the
  floor, `swap()` reverts `InsufficientOutput`, the taker loses only gas.
- loose `minAmountOut` (a generic slippage tolerance the taker itself declared): the fill settles
  within that declared tolerance — not a loss beyond what was disclosed going in.

`test_phantomDepth_emptyVaultCaughtAtQuoteNotAtFill` is a second control: an empty vault is caught
at `quote()` time (`EmptyVault`, `PropAMM.sol:304`), before any fill is attempted — unlike an
adverse-mid write, which `quote()` has no way to flag as adverse.

## What to decide (not decided here)

- **Price band against an independent on-chain reference, checked in `_quote`.** The gap this PoC
  exercises is specifically that nothing compares `mid` to anything external.
- **Per-window withdrawal cap on the vault** (per pair or total), bounding a single-key
  compromise's damage regardless of how adverse the written price is.
- **Updater key isolation** (KMS/HSM, no access from CI or laptops) — reduces how a key gets
  compromised in the first place, doesn't change what the contract allows once it is.
- A simple rate-limit on how fast `mid`/`delta` can move between two updates from the same key is
  weaker than it looks: it can be stepped around (e.g. 1% per 12-second block reaches 25% in about
  5 minutes), and a genuine fast-market move (gaps across exchanges of tens of bps have been
  observed in practice) would need headroom that may undercut the limit's usefulness. Worth
  evaluating against real market data before relying on it alone.

## What this PoC does not cover

- Whether the real, deployed registry (not this test's mock) already enforces a freshness window
  or a divergence bound beyond what `PropAMM.sol` itself checks — its source isn't in this repo,
  only the interface. That would need checking against the live deployment directly.
- Block-builder ordering assumptions (which update lands before which trade) are taken from this
  repo's own documentation, not from an on-chain measurement.

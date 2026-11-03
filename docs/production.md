# Deploying to production

Deploying to production consists, roughly, of three things:

- Deploying the PropAMM contract through the mainnet factory
- Creating, funding and setting up wallets for both the signers (the accounts that will sign quote updates) and the vault that will hold the liquidity/inventory.
- Deploying the quote updater, filling the config with all the addressed and keys obtained above.

## 1. Deploy the PropAMM contract

If there is no factory on your chain yet, deploy one:

```bash
make deploy-factory DEPLOY_RPC_URL=https://... PRIVATE_KEY=0x... FACTORY_OWNER=0x...
```

`FACTORY_OWNER` is the account that can call `disableCreation`, which stops the factory from
creating any more PropAMMs, for good, and emits `CreationDisabled`. It defaults to the deployer.

Note: on Ethereum mainnet the current factory's address is `0x7625E38581124da157586759466E87601416172c`.

Create your PropAMM contract by calling `createPropAMM` on the factory:

```bash
cast send $FACTORY "createPropAMM(address,address,address[],(address,address,address)[])" \
  $OWNER $REGISTRY $UPDATERS $PAIRS \
  --rpc-url $RPC_URL --private-key $DEPLOYER_KEY
```

- `OWNER`: the wallet that will manage the PropAMM afterwards (add pairs, add updaters,
  pause). Can be the same as the deployer.
- `REGISTRY`: the priority update registry the PropAMM reads prices from. On mainnet it is
  `0xDa7AfEeD021EAFC1c1Af9C362dE477DaD0396B81`. It must be a deployed contract on this chain:
  `createPropAMM` reverts with `InvalidOracle` otherwise.
- `UPDATERS`: the wallets allowed to publish prices. Leave it empty, `"[]"`, and add them in
  step 3 once you have created them.
- `PAIRS`: one entry per pair, `"[(TOKEN0,TOKEN1,VAULT)]"`, where `TOKEN0` and `TOKEN1` are
  the two token addresses and `VAULT` is the wallet holding the inventory for that pair.
  Two pairs look like `"[(TOKEN0,TOKEN1,VAULT),(TOKEN0,TOKEN1,VAULT)]"`. Both token addresses
  must be deployed contracts on this chain with at most 36 decimals: creation reverts with
  `NotAToken` for an address without code, and with `UnsupportedDecimals` above 36.

The vault must hold the tokens and have approved the PropAMM to spend both of them. The
PropAMM address does not exist until the call, so either approve it right after creating,
or compute it beforehand with the factory's `computeAddress` (same arguments).

Swaps are push payment: the router transfers the input to the PropAMM and calls `swap` in the
same transaction. Never send tokens to a PropAMM any other way; whatever sits on it can be
swapped by anyone. USDT carries a transfer fee Tether can switch on (currently 0). If it does,
USDT-out swaps revert when the fee takes them below the caller's minimum, and USDT-in swaps
revert unless the PropAMM already holds the fee's worth of USDT (a stray balance, or a caller
that sends more than it swaps): then they fill, and the vault receives the swapped amount less
Tether's fee, selling below its price. The router routes around a PropAMM whose swap reverts,
so this shows up as the pair filling less, not as failed transactions. Watch Tether's fee
itself instead, `cast call 0xdAC17F958D2ee523a2206206994597C13D831ec7 "basisPointsRate()(uint256)"`
(Tether announces a change with its `Params` event), and pause the pair if it is ever non-zero.

So for a WETH/USDC pair on mainnet:

```bash
cast send $FACTORY "createPropAMM(address,address,address[],(address,address,address)[])" \
  $OWNER 0xDa7AfEeD021EAFC1c1Af9C362dE477DaD0396B81 "[]" \
  "[(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2,0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48,$VAULT)]" \
  --rpc-url $RPC_URL --private-key $DEPLOYER_KEY
```

You do not need to add all the pairs upfront on contract creation. You can both and or remove pairs by having the owner calling the appropriate contract functions.

## 2. Create one wallet per pair and fund it with ETH

Each pair publishes its price from its own wallet. Make a fresh one per pair and send it ETH: every price update is a transaction and pays gas.

## 3. Authorize those wallets on the PropAMM

From the owner account, once per wallet:

```bash
cast send $PROPAMM "addUpdater(address)" $UPDATER_ADDRESS --rpc-url $RPC_URL --private-key $OWNER_KEY
```

`addUpdater` reverts with `UpdaterAlreadyAuthorized` for a wallet the registry already
authorizes, and `removeUpdater` with `UpdaterNotAuthorized` for one it does not, so that every
`UpdaterAuthorized`/`UpdaterRevoked` the PropAMM logs is a real change. Re-running this step for
a wallet that is already there fails instead of doing nothing, and in a batch (a Safe multisend)
one such call fails the whole batch. Check first with
`cast call $REGISTRY "isUpdater(address,address)(bool)" $PROPAMM $UPDATER_ADDRESS --rpc-url $RPC_URL`.

## 4. Get API keys from the builders

The api to send builders quote updates is permissioned, behind an API key. You will have to Ask each builder for one:

- Titan: `wss://eu.rpc.titanbuilder.xyz/ws/sendquoteupdate`
- Quasar: `wss://rpc.quasar.win/ws/sendquoteupdate`
- BuilderNet: `wss://direct-eu.buildernet.org/ws/sendquoteupdate`

## 5. Fill in the config on the server

Clone the repo, then in `deploy/`:

```bash
cp .env.example .env
cp config.example.toml config/config.toml
cp alertmanager/slack-webhook.example alertmanager/slack-webhook
```

Edit the three files:

- `.env`, one line per variable:
  - `RPC_URL`: the Ethereum RPC the updater reads the chain through.
  - `RPC_WS_URL`: the same node's WebSocket endpoint (`wss://…`), so it pushes each new
    block to the updater instead of being polled for it four times a second. Optional but
    worth setting: the run confirms it with `[head] subscribed to new heads at <host>`, and
    falls back to polling whenever the socket is down.
  - `UPDATER_KEY_<PAIR>`: the private key of each wallet from step 2, one variable per pair.
    The name is yours to pick; the pair's config refers to it by that name (`key_env`).
    For example `UPDATER_KEY_WETH_USDC=0x...` and `UPDATER_KEY_USDC_USDT=0x...`.
  - `POSTGRES_PASSWORD`: password for the Postgres the updater records into. Any string.
  - `GRAFANA_ADMIN_PASSWORD`: password for Grafana's `admin` user.
  - `BACKOFFICE_BIND` and `GRAFANA_BIND`: the IP of this server the backoffice (port 8088)
    and Grafana (port 3000) listen on. Neither has a login, so use a private IP such as the
    server's tailnet address. `127.0.0.1` keeps them reachable only from the server itself.
- `config/config.toml`: the PropAMM address, the builders with their API keys, and the
  pairs. Pairs can also be added later from the backoffice.
- `alertmanager/slack-webhook`: the Slack webhook URL alerts go to.

## 6. Start it

```bash
docker compose build
docker compose run --rm updater --check
docker compose up -d
```

`--check` connects to the chain and reports anything wrong (a wallet not authorized or
without ETH, a pair the contract doesn't have, a typo in the config).

## 7. Inspect Grafana and the backoffice to manage updater/pair settings 

Open `http://<IP from .env>:8088` to go into the backoffice and change pair settings, pair curves, etc.

If you add a new pair (and thus a new updater), the new updater key goes in `.env` first, then `docker compose up -d` so the updater picks it up.

Grafana is at `http://<IP from .env>:3000`. Day-to-day commands (reload, logs, updates) are in
[`deploy/README.md`](../deploy/README.md).

## Moving a PropAMM to another registry

`setOracle` moves where the PropAMM reads prices from and where `addUpdater`/`removeUpdater`
act. It neither copies nor revokes the wallets authorized on the old registry: the registry
records them under the PropAMM's address, so they stay live there, and pointing the PropAMM back
at the old registry would let every one of them price it again. The first mainnet registry
(`0xDa7AfeeD01fe…8C5F`) has a known vulnerability, so never point a PropAMM back at it;
`removeUpdaterFrom` revokes there without doing so. From the owner account, in this order:

1. List the wallets on the old registry. Its own `UpdaterAdded(target, updater)` log, filtered
   on the PropAMM as `target`, has every wallet ever added there (drop those a later
   `UpdaterRemoved` revoked); or check the wallets you know, one by one:

   ```bash
   cast call $OLD_REGISTRY "isUpdater(address,address)(bool)" $PROPAMM $UPDATER_ADDRESS --rpc-url $RPC_URL
   ```

2. Point the PropAMM at the new registry. Quotes stop until step 3's wallets publish there: with
   no fresh price on the new registry, every quote and swap reverts.

   ```bash
   cast send $PROPAMM "setOracle(address)" $NEW_REGISTRY --rpc-url $RPC_URL --private-key $OWNER_KEY
   ```

3. Authorize each wallet on the new registry; `addUpdater` now acts there.

   ```bash
   cast send $PROPAMM "addUpdater(address)" $UPDATER_ADDRESS --rpc-url $RPC_URL --private-key $OWNER_KEY
   ```

4. Revoke each wallet on the old registry, without pointing back at it.

   ```bash
   cast send $PROPAMM "removeUpdaterFrom(address,address)" $OLD_REGISTRY $UPDATER_ADDRESS --rpc-url $RPC_URL --private-key $OWNER_KEY
   ```

5. Point the quote updater at the new registry: `registry = "<NEW_REGISTRY>"` at the top of
   `config/config.toml` (or `--registry`). Then `docker compose run --rm updater --check` asks
   that registry whether each wallet is authorized, and `docker compose up -d` restarts it.

A PropAMM still on an implementation without `removeUpdaterFrom` revokes on the old registry by
pointing back at it, paused so nothing trades in between:
`pause()`, `setOracle(OLD)`, `removeUpdater(wallet)` for each, `setOracle(NEW)`, `unpause()`.

## Next steps

The pairs quote with the pricing models the library ships. To tune their settings, change
them from the backoffice. To change the pricing itself, write your own model or adjust the
example one: [pricing.md](pricing.md) covers what the shipped models do, how to write one,
and what the library gives you to do it.

#!/usr/bin/env bash
# Spin up your own PropAMM on a local chain and quote it with your own pricing model.
#
#   ./quickstart.sh                 deploy the contracts on anvil, build and run example/
#   QUICKSTART_SECONDS=40 ./quickstart.sh   same, but stop after 40s and print what happened
#
# Needs: foundry (anvil, forge, cast), Rust (rustup; the toolchain is pinned per repo), internet
# for the Binance price stream. Everything on chain happens on 127.0.0.1:8545.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")" && pwd)
RPC=http://127.0.0.1:8545
REGISTRY=0xDa7AfEeD021EAFC1c1Af9C362dE477DaD0396B81          # Flashbots' priority update registry
FACTORY=0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512           # where a fresh anvil puts the factory
# anvil account 0: deploys everything and is the updater the PropAMM authorizes. Public test key.
UPDATER_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

echo "== 1/3 local chain and contracts (anvil, registry, factory, one PropAMM with a USDC/USDT pair)"
make -C "$ROOT" local >"$ROOT/.quickstart-contracts.log" 2>&1 || {
  tail -20 "$ROOT/.quickstart-contracts.log"; echo "contracts deploy failed; full log: .quickstart-contracts.log"; exit 1; }
PROPAMM=$(cast call $FACTORY 'allPropAMMs(uint256)(address)' 0 --rpc-url $RPC)
echo "   PropAMM at $PROPAMM"

echo "== 2/3 build example/ and point its config at that PropAMM"
cd "$ROOT/example"
sed "s/__PROPAMM__/$PROPAMM/" config.local.toml > .local.toml
cargo build -q
export UPDATER_KEY_USDC_USDT=$UPDATER_KEY
./target/debug/my-propamm --config .local.toml --registry $REGISTRY --check

echo "== 3/3 quote it: one updateState transaction per 12s, mining a block each (ctrl-c to stop)"
CMD=(./target/debug/my-propamm --config .local.toml --registry $REGISTRY --mine --interval 12)
if [ -n "${QUICKSTART_SECONDS:-}" ]; then
  "${CMD[@]}" >"$ROOT/.quickstart-run.log" 2>&1 & PID=$!
  sleep "$QUICKSTART_SECONDS"; kill -INT $PID; wait $PID || true
  echo; echo "--- what the updater logged"; grep -v "^$" "$ROOT/.quickstart-run.log" | tail -25
  echo; echo "--- what the chain says now"
  USDC=0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48; USDT=0xdAC17F958D2ee523a2206206994597C13D831ec7
  echo -n "isActive(USDC,USDT) = "; cast call $PROPAMM 'isActive(address,address)(bool)' $USDC $USDT --rpc-url $RPC
  echo -n "quote(USDC,USDT,1000000) = "; cast call $PROPAMM 'quote(address,address,uint256)(uint256)' $USDC $USDT 1000000 --rpc-url $RPC
  make -C "$ROOT" local-down >/dev/null 2>&1
else
  exec "${CMD[@]}"
fi

"""What the mocks, the scenario and the checks must agree on."""

import subprocess

CHAIN_ID = 1
# Blocks are numbered from START_BLOCK and stamped GENESIS_TS + 12s per block, so every run
# sees the same chain and signs the same bytes: an update's timestamp is its parent's plus
# 12s, and the fee comes from BASE_FEE.
START_BLOCK = 1000
GENESIS_TS = 1_800_000_000
BLOCK_TIME = 12
BASE_FEE = 1_000_000_000  # 1 gwei

# The default registry (the scenario does not set one) and the PropAMM the pairs quote on.
REGISTRY = "0xda7afeed021eafc1c1af9c362de477dad0396b81"
TARGET = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"
VAULT = "0x00000000000000000000000000000000000000aa"

USDC = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
USDT = "0xdac17f958d2ee523a2206206994597c13d831ec7"
WETH = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"
TOKENS = {USDC: ("USDC", 6), USDT: ("USDT", 6), WETH: ("WETH", 18)}

# anvil's well-known dev keys #0 and #2: public test keys, not secrets. #1 is skipped
# because its address is TARGET.
KEYS = {
    "UPDATER_KEY_USDC_USDT": "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    "UPDATER_KEY_WETH_USDC": "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
}
UPDATERS = {
    "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266": "USDC/USDT",
    "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc": "WETH/USDC",
}

BUILDERS = [("mock-a", "key-a"), ("mock-b", "key-b")]


def cast(*args):
    """foundry's cast: keccak and transaction decoding without a Python crypto dependency."""
    return subprocess.check_output(["cast", *args], text=True).strip()


def block_ts(n):
    return GENESIS_TS + BLOCK_TIME * (n - START_BLOCK)

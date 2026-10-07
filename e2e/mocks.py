"""Everything the quote updater talks to, mocked in one process so the pieces share state.

- A JSON-RPC chain over HTTP. Blocks advance only when the scenario mines one, so two runs
  see the same chain. eth_call answers the registry, the PropAMM target and the ERC-20 views
  the updater reads.
- Builders speaking the maker protocol (protobuf over WebSocket, see builder.rs). They
  record and ack every update, and hand the latest one for block N to the chain, which
  includes it when N is mined, the way a builder that won the block would. That is what
  makes the updater's `getState` landing check a real round trip.
- Binance's `<symbol>@bookTicker` stream, sending the current book every 200ms: Binance
  sends only on change, but the updater drops a feed that has gone quiet, so the mock keeps
  it fresh.
- A control API under /control on the RPC port, for the scenario: mine, move a price, kill
  a builder, dump what happened.

Listens on 127.0.0.1 only. Run by scenario.py with its ports as a JSON argument.

With `anvil_rpc` in the argument (`make quickstart`), the chain is a real anvil instead: the
builders still collect updates, and every `mine_every` seconds the latest one per quote for
anvil's next block is sent to anvil and a block is mined with the timestamp those updates
were signed for, the way a builder that won the block would include them. `binance_port` is
optional there, so the updater can read the real exchange.
"""

import asyncio
import copy
import json
import sys
import time

import aiohttp
import websockets
from aiohttp import web
from websockets.asyncio.server import serve

from common import (BASE_FEE, CHAIN_ID, REGISTRY, START_BLOCK, TARGET, TOKENS, USDC, USDT, VAULT,
                    WETH, block_ts, cast)

# A post-Prague block as anvil serves it: the updater's RPC client deserializes every
# header field, so the shape has to be complete. number, timestamp, the hashes and the base
# fee are filled in per block.
BLOCK = {
    "baseFeePerGas": hex(BASE_FEE), "blobGasUsed": "0x0", "difficulty": "0x0",
    "excessBlobGas": "0x0", "extraData": "0x", "gasLimit": "0x1c9c380", "gasUsed": "0x0",
    "logsBloom": "0x" + "00" * 256, "miner": "0x" + "00" * 20, "mixHash": "0x" + "00" * 32,
    "nonce": "0x0000000000000000", "parentBeaconBlockRoot": "0x" + "00" * 32,
    "receiptsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
    "requestsHash": "0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
    "size": "0x267",
    "stateRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
    "totalDifficulty": "0x0", "transactions": [],
    "transactionsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
    "uncles": [], "withdrawals": [],
    "withdrawalsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
}

SIGS = ["isUpdater(address,address)", "getState(uint256,uint32,uint32)", "pairVaults(uint256)",
        "vaultFor(address,address)", "getPairs()", "symbol()", "decimals()", "balanceOf(address)",
        "updateState(address,uint256,uint32,uint256[])"]

# What the target serves, as prod's answers getPairs(): the vault exporter watches these
# vaults whether or not the config quotes them. The same two pairs the scenario configures,
# so the exporter's series are the ones the metrics check already expects.
SERVED_PAIRS = [(USDC, WETH), (USDC, USDT)]

# The USD prices the CoinGecko stand-in answers, so the vault's USD value series exist
# without the exporter ever reaching the real API from a test.
USD_PRICES = {WETH: 2000.0, USDC: 1.0, USDT: 1.0}
SIG_OF = {cast("sig", s)[2:]: s for s in SIGS}
UPDATE_STATE = next(k for k, s in SIG_OF.items() if s.startswith("updateState"))

# ---- ABI ----


def u256(v):
    return v.to_bytes(32, "big")


def address_word(a):
    return bytes(12) + bytes.fromhex(a[2:])


def abi_string(s):
    b = s.encode()
    return u256(32) + u256(len(b)) + b + bytes((32 - len(b) % 32) % 32)


def abi_state(ts, values):
    """getState's return: (uint32 ts, uint256[] slots)."""
    return u256(ts) + u256(64) + u256(len(values)) + b"".join(u256(v) for v in values)


def abi_pairs(pairs):
    """getPairs's return: a dynamic (address, address)[], offset then length then the words."""
    return u256(32) + u256(len(pairs)) + b"".join(address_word(a) + address_word(b) for a, b in pairs)


def words(data):
    return [data[i:i + 32] for i in range(0, len(data), 32)]


# ---- protobuf: the maker protocol's two messages ----


def get_varint(buf, pos):
    v, shift = 0, 0
    while True:
        b = buf[pos]
        pos += 1
        v |= (b & 0x7F) << shift
        if not b & 0x80:
            return v, pos
        shift += 7


def put_varint(v):
    out = bytearray()
    while True:
        b, v = v & 0x7F, v >> 7
        if v == 0:
            out.append(b)
            return bytes(out)
        out.append(b | 0x80)


def decode_update(buf):
    """PWebsocketQuoteUpdateV1Args. An absent field is its default, as proto3 encodes it."""
    msg = {"tx": b"", "block": 0, "uuid": b"", "seq": 0, "no_cross_region": False,
           "asset_pairs": [], "quote_address": b"", "pools": []}
    pos = 0
    while pos < len(buf):
        tag, pos = get_varint(buf, pos)
        field, wire = tag >> 3, tag & 7
        if wire == 0:
            v, pos = get_varint(buf, pos)
            key = {2: "block", 4: "seq", 5: "no_cross_region"}.get(field)
            if key:
                msg[key] = bool(v) if key == "no_cross_region" else v
        elif wire == 2:
            n, pos = get_varint(buf, pos)
            b, pos = buf[pos:pos + n], pos + n
            if field in (6, 8):
                msg["asset_pairs" if field == 6 else "pools"].append(b.hex())
            elif field in (1, 3, 7):
                msg[{1: "tx", 3: "uuid", 7: "quote_address"}[field]] = b
        else:
            raise ValueError(f"unexpected wire type {wire}")
    return msg


def encode_ack(uuid, seq):
    """PWebsocketQuoteUpdateV1Response: uuid, seq, and when it was received (UNIX ns)."""
    out = b"\x0a" + put_varint(len(uuid)) + uuid
    if seq:
        out += b"\x10" + put_varint(seq)
    return out + b"\x18" + put_varint(time.time_ns())


# ---- shared state ----


class World:
    def __init__(self):
        self.head = START_BLOCK
        self.nonces = {}
        self.state = {}  # (target, lane) -> [(block, ts, values)]
        self.pending = {}  # block -> {uuid: latest raw tx}: one update per quote identity
        self.events = []
        self.rpc_calls = {}
        self.unknown = []
        self.prices = {}  # symbol -> (bid, ask)
        self.builder_conns = {}
        self.builder_down = set()
        self.mined = []

    def event(self, kind, **fields):
        self.events.append({"t": time.time(), "kind": kind, **fields})

    def block(self, n):
        b = copy.deepcopy(BLOCK)
        b.update(number=hex(n), timestamp=hex(block_ts(n)),
                 hash="0x" + n.to_bytes(32, "big").hex(),
                 parentHash="0x" + (n - 1).to_bytes(32, "big").hex())
        return b

    def mine(self):
        n = self.head + 1
        # Every builder was sent the same bytes, so each distinct transaction is included once.
        for raw in sorted(set(self.pending.pop(n, {}).values())):
            tx = json.loads(cast("decode-tx", raw))
            data = bytes.fromhex(tx["input"][2:])
            assert data[:4].hex() == UPDATE_STATE, "a builder was sent something other than updateState"
            w = words(data[4:])
            target, lane, ts = "0x" + w[0][12:].hex(), int.from_bytes(w[1], "big"), int.from_bytes(w[2], "big")
            values = [int.from_bytes(x, "big") for x in w[5:5 + int.from_bytes(w[4], "big")]]
            sender = tx["signer"].lower()
            nonce = int(tx["nonce"], 16) if isinstance(tx["nonce"], str) else tx["nonce"]
            # As the registry and the chain would: only for the block its timestamp names,
            # and only at the sender's next nonce.
            accepted = ts == block_ts(n) and nonce == self.nonces.get(sender, 0)
            if accepted:
                self.nonces[sender] = nonce + 1
                self.state.setdefault((target, lane), []).append((n, ts, values))
            self.mined.append({"block": n, "sender": sender, "nonce": nonce, "lane": hex(lane),
                               "ts": ts, "values": values, "accepted": accepted, "raw": raw})
        self.head = n
        self.event("mined", block=n)
        return n


W = World()

# ---- JSON-RPC ----


def eth_call(call, block_tag):
    to = call["to"].lower()
    data = bytes.fromhex((call.get("data") or call.get("input"))[2:])
    sig, args = SIG_OF.get(data[:4].hex()), data[4:]
    if to == REGISTRY and sig == "isUpdater(address,address)":
        return u256(1)
    if to == REGISTRY and sig == "getState(uint256,uint32,uint32)":
        # Scoped to msg.sender, like the registry: the updater reads it as the target.
        sender = (call.get("from") or "").lower()
        lane = int.from_bytes(args[:32], "big")
        at = W.head if block_tag in (None, "latest", "pending") else int(block_tag, 16)
        history = [h for h in W.state.get((sender, lane), []) if h[0] <= at]
        return abi_state(*(history[-1][1:] if history else (0, [])))
    if to == TARGET and sig in ("pairVaults(uint256)", "vaultFor(address,address)"):
        return address_word(VAULT)
    if to == TARGET and sig == "getPairs()":
        return abi_pairs(SERVED_PAIRS)
    if to in TOKENS and sig == "symbol()":
        return abi_string(TOKENS[to][0])
    if to in TOKENS and sig == "decimals()":
        return u256(TOKENS[to][1])
    if to in TOKENS and sig == "balanceOf(address)":
        return u256(10**30)
    W.unknown.append({"to": to, "selector": data[:4].hex(), "sig": sig})
    raise KeyError(f"no mock for eth_call to {to} ({sig or data[:4].hex()})")


def dispatch(method, params):
    W.rpc_calls[method] = W.rpc_calls.get(method, 0) + 1
    if method == "eth_chainId":
        return hex(CHAIN_ID)
    if method == "eth_blockNumber":
        return hex(W.head)
    if method == "eth_getBlockByNumber":
        tag = params[0]
        return W.block(W.head if tag in ("latest", "pending", "safe", "finalized") else min(int(tag, 16), W.head))
    if method == "eth_getCode":
        return "0x6001600052" if params[0].lower() in (REGISTRY, TARGET, *TOKENS) else "0x"
    if method == "eth_getTransactionCount":
        return hex(W.nonces.get(params[0].lower(), 0))
    if method == "eth_getBalance":
        return hex(10 * 10**18)
    if method == "eth_call":
        return "0x" + eth_call(params[0], params[1] if len(params) > 1 else None).hex()
    W.unknown.append({"method": method, "params": params})
    raise KeyError(f"{method} is not mocked")


async def rpc(request):
    body = await request.json()
    out = []
    for req in body if isinstance(body, list) else [body]:
        try:
            out.append({"jsonrpc": "2.0", "id": req["id"],
                        "result": dispatch(req["method"], req.get("params", []))})
        except Exception as e:  # answered as a node answers, so the updater sees an RPC error
            out.append({"jsonrpc": "2.0", "id": req["id"],
                        "error": {"code": -32000, "message": str(e)}})
    return web.json_response(out if isinstance(body, list) else out[0])


async def token_price(request):
    """CoinGecko's /simple/token_price/{platform}: {address: {"usd": price}} per address asked,
    keyed lower-case as the real API answers. `[settings.endpoints] coingecko` points the
    updater here, so the vault exporter's once-a-minute pricing never leaves the machine."""
    asked = request.query.get("contract_addresses", "").lower().split(",")
    return web.json_response({a: {"usd": USD_PRICES[a]} for a in asked if a in USD_PRICES})


async def control(request):
    op, q = request.match_info["op"], request.query
    if op == "mine":
        return web.json_response({"head": W.mine()})
    if op == "price":
        W.prices[q["symbol"].upper()] = (q["bid"], q["ask"])
        W.event("price", symbol=q["symbol"].upper(), bid=q["bid"], ask=q["ask"])
        return web.json_response({"ok": True})
    if op == "kill-builder":
        W.builder_down.add(q["name"])
        for ws in list(W.builder_conns.get(q["name"], ())):
            await ws.close()
        W.event("builder_killed", builder=q["name"])
        return web.json_response({"ok": True})
    if op == "dump":
        return web.json_response({"events": W.events, "rpc_calls": W.rpc_calls,
                                  "unknown": W.unknown, "mined": W.mined, "head": W.head})
    return web.json_response({"error": f"unknown op {op}"}, status=404)


# ---- builders ----


def builder(name, api_key):
    async def handler(ws):
        path, auth = ws.request.path, ws.request.headers.get("Authorization")
        if name in W.builder_down or path != "/ws/sendquoteupdate" or auth != api_key:
            # A killed builder still completes the WebSocket handshake before closing, so
            # the updater briefly counts it live again on each redial.
            W.event("builder_refused", builder=name, path=path, auth=auth)
            await ws.close(code=1008, reason="refused")
            return
        W.builder_conns.setdefault(name, set()).add(ws)
        W.event("builder_connected", builder=name)
        try:
            async for frame in ws:
                if not isinstance(frame, bytes):
                    W.event("builder_text_frame", builder=name, text=frame)
                    continue
                m = decode_update(frame)
                W.event("update", builder=name, block=m["block"], uuid=m["uuid"].hex(),
                        seq=m["seq"], tx=m["tx"].hex(), cancel=not m["tx"],
                        no_cross_region=m["no_cross_region"], asset_pairs=m["asset_pairs"],
                        quote_address=m["quote_address"].hex(), pools=m["pools"])
                slot = W.pending.setdefault(m["block"], {})
                if m["tx"]:
                    slot[m["uuid"].hex()] = "0x" + m["tx"].hex()
                else:  # a cancel withdraws that quote from the block
                    slot.pop(m["uuid"].hex(), None)
                await ws.send(encode_ack(m["uuid"], m["seq"]))
        except websockets.ConnectionClosed:
            pass
        finally:
            W.builder_conns[name].discard(ws)
            W.event("builder_disconnected", builder=name)
    return handler


# ---- Binance ----


async def binance(ws):
    symbol = ws.request.path.rsplit("/", 1)[-1].split("@")[0].upper()  # /ws/<symbol>@bookTicker
    W.event("binance_subscribed", symbol=symbol, path=ws.request.path)
    u = 0
    try:
        while True:
            if symbol in W.prices:
                bid, ask = W.prices[symbol]
                u += 1
                await ws.send(json.dumps({"u": u, "s": symbol, "b": bid, "B": "10.0", "a": ask, "A": "10.0"}))
            await asyncio.sleep(0.2)
    except websockets.ConnectionClosed:
        pass


async def auto_mine(every):
    """A block every `every` seconds, for a binary run by hand against the mocks (`make
    mocks`): the e2e scenario mines on its own schedule and never sets this."""
    while True:
        await asyncio.sleep(every)
        W.mine()


async def mine_on_anvil(url, every):
    """`auto_mine` against a real anvil (`--no-mining`): every `every` seconds, the updates
    the builders hold for anvil's next block are sent to it and a block is mined stamped with
    the timestamp they were signed for (the parent's plus 12s, as the updater computes it),
    so the registry's read-side check passes and `isActive` is true in that block. A block
    with no update is mined the same way, so the chain keeps moving and the updater keeps
    quoting the block after."""
    async def call(session, method, *params):
        async with session.post(url, json={"jsonrpc": "2.0", "id": 1, "method": method,
                                           "params": list(params)}) as r:
            body = await r.json()
            if "error" in body:
                raise RuntimeError(f"{method}: {body['error']}")
            return body["result"]

    async with aiohttp.ClientSession() as session:
        while True:
            await asyncio.sleep(every)
            head = await call(session, "eth_getBlockByNumber", "latest", False)
            n = int(head["number"], 16)
            next_ts = int(head["timestamp"], 16) + 12
            # Updates for blocks that already passed are stale: the builder would drop them.
            for stale in [b for b in W.pending if b <= n]:
                W.pending.pop(stale)
            raws = sorted(set(W.pending.pop(n + 1, {}).values()))
            if raws:
                tx = json.loads(cast("decode-tx", raws[0]))
                w = words(bytes.fromhex(tx["input"][2:])[4:])
                next_ts = int.from_bytes(w[2], "big")
            # Whatever else is waiting in anvil's pool (a swap from `make swap`) goes after
            # the updates, as a builder orders its block: the pool is emptied and refilled,
            # updates first, each sender's own transactions in nonce order.
            pool = await call(session, "txpool_content")
            waiting = []
            for sender in pool.get("pending", {}).values():
                for nonce in sorted(sender, key=int):
                    waiting.append(await call(session, "eth_getRawTransactionByHash", sender[nonce]["hash"]))
            await call(session, "anvil_dropAllTransactions")
            await call(session, "evm_setNextBlockTimestamp", next_ts)
            included = []
            for raw in raws + waiting:
                try:
                    included.append(await call(session, "eth_sendRawTransaction", raw))
                except RuntimeError as err:
                    W.event("anvil_rejected", block=n + 1, error=str(err))
            await call(session, "anvil_mine")
            W.event("mined", block=n + 1, ts=next_ts, included=included)


async def main():
    cfg = json.loads(sys.argv[1])
    W.prices.update({s: tuple(p) for s, p in cfg["prices"].items()})
    app = web.Application()
    app.router.add_post("/", rpc)
    app.router.add_get("/simple/token_price/{platform}", token_price)
    app.router.add_route("*", "/control/{op}", control)
    runner = web.AppRunner(app)
    await runner.setup()
    await web.TCPSite(runner, "127.0.0.1", cfg["rpc_port"]).start()
    for b in cfg["builders"]:
        await serve(builder(b["name"], b["api_key"]), "127.0.0.1", b["port"])
    if cfg.get("binance_port"):
        await serve(binance, "127.0.0.1", cfg["binance_port"])
    print("READY", flush=True)
    if cfg.get("mine_every"):  # held: the loop keeps a weak ref
        if cfg.get("anvil_rpc"):
            W.miner = asyncio.create_task(mine_on_anvil(cfg["anvil_rpc"], cfg["mine_every"]))
        else:
            W.miner = asyncio.create_task(auto_mine(cfg["mine_every"]))
    await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())

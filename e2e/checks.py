"""What a recorded run must show, and what two runs of different binaries must share."""

import json
import pathlib
import re
from decimal import Decimal, getcontext

from common import BUILDERS, REGISTRY, TARGET, TOKENS, UPDATERS, USDC, USDT, VAULT, WETH, block_ts, cast

getcontext().prec = 60
_decoded = {}


def lane(a, b):
    """keccak256(token0 ++ token1) over the address-sorted pair, as PropAMM derives it."""
    a, b = sorted([a, b])
    return int(cast("keccak", "0x" + a[2:] + b[2:]), 16)


def decode(raw):
    """The signed transaction, with its updateState(address,uint256,uint32,uint256[]) args."""
    if raw not in _decoded:
        tx = json.loads(cast("decode-tx", raw))
        data = bytes.fromhex(tx["input"][2:])
        w = [data[4 + i:36 + i] for i in range(0, len(data) - 4, 32)]
        n = int.from_bytes(w[4], "big")
        tx["call"] = {"target": "0x" + w[0][12:].hex(), "lane": int.from_bytes(w[1], "big"),
                      "ts": int.from_bytes(w[2], "big"),
                      "values": [int.from_bytes(x, "big") for x in w[5:5 + n]]}
        _decoded[raw] = tx
    return _decoded[raw]


def num(v):
    return int(v, 16) if isinstance(v, str) else int(v)


def inverted(bid, ask):
    """What the WETH/USDC lane publishes for a WETH-in-USDC book, at 1e18.

    The lane carries USDC priced in WETH, so each side of the book is inverted and then
    averaged. The delta is the book's relative half-spread, which inversion leaves alone.
    """
    bid, ask = Decimal(bid), Decimal(ask)
    return [10**18 * (ask - bid) / (ask + bid), (10**18 / ask + 10**18 / bid) / 2]


def tilted(bid, ask, half_spread, tilt):
    """What the `tilted` kind publishes for the WETH/USDC lane: the configured half-spread
    as the delta, and the inverted mid tilted by tilt × (base share − 0.5).

    The mock's vault holds 1e30 raw of every token, so its base share at any sane price is
    a few parts per billion: the tilt is (almost exactly) −tilt/2 in market terms, which
    the inverted lane carries as a mid divided by (1 − skew). The updater does this in
    fixed point off an f64 factor; the tolerance in `check` covers the last digits.
    """
    _, mid = inverted(bid, ask)
    market_mid = Decimal(10**18) / mid
    base = Decimal(10**30) / Decimal(10**TOKENS[WETH][1])
    quote = Decimal(10**30) / Decimal(10**TOKENS[USDC][1])
    share = base * market_mid / (base * market_mid + quote)
    skew = Decimal(tilt) * (share - Decimal("0.5"))
    return [10**18 * Decimal(half_spread), mid / (1 - skew)]


def load(out):
    out = pathlib.Path(out)
    return (out, json.loads((out / "world.json").read_text()),
            (out / "run.out").read_text(), (out / "check.out").read_text())


def check(out_dir, start_price, moved_price, custom=False):
    """Prints one line per check; returns whether all passed. `custom` is the `tilted` run."""
    out, world, run, report = load(out_dir)
    results = []

    def ok(name, cond, detail=""):
        results.append((bool(cond), name, detail))

    events = world["events"]
    steps = {s["step"]: s for s in world["timeline"]}
    updates = [e for e in events if e["kind"] == "update"]
    killed = next(e for e in events if e["kind"] == "builder_killed")
    live, dead = BUILDERS[0][0], killed["builder"]
    sigint = steps["sigint"]["t"]
    lanes = {"USDC/USDT": lane(USDC, USDT), "WETH/USDC": lane(WETH, USDC)}

    ok("--check exits 0", (out / "check.rc").read_text().strip() == "0")
    ok("--check: both updaters authorized", len(re.findall(r"^\S+\s+0x\w+ .* yes ", report, re.M)) == 2)
    ok("--check sends nothing", "nothing sent (--check)" in report)
    ok("exits 0 on SIGINT", steps["exited"]["rc"] == 0, str(steps["exited"]["rc"]))
    for pair in lanes:
        ok(f"[{pair}] quoting with 2/2 builders live at startup", f"[{pair}] quoting with 2/2 builders live" in run)
    ok("no RPC call or eth_call the mocks could not answer", not world["unknown"], json.dumps(world["unknown"][:3]))
    bad = [line for line in run.splitlines() if re.search(r"panick|backtrace|\berror\b|Error:", line)]
    ok("no panics or errors in the log", not bad, "\n".join(bad[:5]))

    seqs, rising = {}, True
    for e in updates:
        key = (e["builder"], e["uuid"])
        rising &= seqs.get(key, -1) < e["seq"]
        seqs[key] = e["seq"]
    ok("replacement_seq_number strictly increases per quote identity", rising)
    ok("one quote identity per pair per builder", len(seqs) == 2 * len(BUILDERS), str(len(seqs)))

    both_up = [e for e in updates if e["t"] < killed["t"] - 0.5 and not e["cancel"]]
    sent = {b: {(e["block"], e["tx"]) for e in both_up if e["builder"] == b} for b, _ in BUILDERS}
    ok("every builder receives the same signed bytes for each block", sent[live] == sent[dead],
       f"{live}-only {len(sent[live] - sent[dead])}, {dead}-only {len(sent[dead] - sent[live])}")

    distinct = sorted({(e["block"], e["tx"]) for e in updates if not e["cancel"]})
    problems = []
    for block, tx in distinct:
        d = decode("0x" + tx)
        pair, call = UPDATERS.get(d["signer"].lower()), d["call"]
        for good, what in [(d["to"].lower() == REGISTRY, "to is the registry"),
                           (num(d["chainId"]) == 1, "chain id 1"),
                           (pair is not None, f"signer {d['signer']} is a configured updater"),
                           (call["target"] == TARGET, "calldata target"),
                           (pair and call["lane"] == lanes[pair], "calldata lane"),
                           (call["ts"] == block_ts(block), f"ts {call['ts']} is block {block}'s"),
                           (len(call["values"]) == 2, "two slots, [delta, mid]")]:
            if not good:
                problems.append(f"block {block}: {what}")
    ok(f"all {len(distinct)} distinct transactions decode right (to, chain, signer, target, lane, ts)",
       not problems, "; ".join(problems[:5]))

    # A transaction from an unknown signer has already failed above; the price checks read
    # only the configured updaters', so one bad signature is a FAIL line, not a crash.
    by_pair = {pair: [] for pair in lanes}
    for block, tx in distinct:
        d = decode("0x" + tx)
        if d["signer"].lower() in UPDATERS:
            by_pair[UPDATERS[d["signer"].lower()]].append(d["call"]["values"])
    fixed = {tuple(v) for v in by_pair["USDC/USDT"]}
    ok("fixed pair publishes exactly [0.0002, 1.0001] at 1e18", fixed == {(2 * 10**14, 10001 * 10**14)}, str(fixed))
    feed = by_pair["WETH/USDC"] or [[None, None]]
    for label, got, price in [("before the move", feed[0], start_price), ("after the move", feed[-1], moved_price)]:
        if custom:
            import scenario
            want = tilted(*price, scenario.TILTED["half_spread"], scenario.TILTED["tilt"])
            # The delta is exact; the tilted mid goes through an f64 factor at 15 digits.
            close = (None not in got and got[0] == want[0]
                     and abs(got[1] - want[1]) <= want[1] * Decimal("1e-8"))
            ok(f"tilted pair publishes its half-spread and the tilted inverted {'/'.join(price)} mid {label}",
               close, f"{got} vs [{want[0]:.2f}, {want[1]:.2f}]")
        else:
            want = inverted(*price)
            ok(f"feed pair publishes the inverted {'/'.join(price)} book {label}",
               None not in got and all(abs(g - w) <= 1 for g, w in zip(got, want)),
               f"{got} vs [{want[0]:.2f}, {want[1]:.2f}]")

    mined_blocks = [e["block"] for e in events if e["kind"] == "mined"]
    included = world["mined"]
    ok("every included update is accepted (right ts, right nonce)",
       included and all(m["accepted"] for m in included), str([m for m in included if not m["accepted"]][:2]))
    per_block = {b: sorted(UPDATERS.get(m["sender"], m["sender"]) for m in included if m["block"] == b)
                 for b in mined_blocks}
    ok("each mined block includes both pairs", all(v == sorted(lanes) for v in per_block.values()), str(per_block))
    for pair in lanes:
        landed = {int(b) for b in re.findall(rf"\[{re.escape(pair)}\] block (\d+): update landed", run)}
        ok(f"[{pair}] reports 'update landed' for every mined block", set(mined_blocks) <= landed,
           f"mined {mined_blocks}, landed {sorted(landed)}")
    ok("no update reported as not landing", not re.search(r"did not land|not landing|unverified", run))
    nonces = {}
    for m in included:
        nonces.setdefault(m["sender"], []).append(m["nonce"])
    ok("nonces run 0, 1, 2, ... per updater", all(v == list(range(len(v))) for v in nonces.values()), str(nonces))

    after_kill = [e for e in updates if killed["t"] + 0.5 < e["t"] < sigint and not e["cancel"]]
    ok(f"{live} keeps receiving updates after {dead} is killed",
       {e["builder"] for e in after_kill} == {live} and len({e["block"] for e in after_kill}) >= 2)
    ok(f"the log reports {dead} down", re.search(rf"{dead}\s+down", run) is not None)
    cancels = {e["uuid"] for e in updates if e["cancel"] and e["builder"] == live and e["t"] >= sigint - 0.1}
    ok(f"SIGINT sends {live} a cancel for both pairs", len(cancels) == 2, str(cancels))

    metrics = (out / "metrics.txt").read_text()
    prefix = "quote_updater_"
    series = set(re.findall(rf"^({prefix}\w+)", metrics, re.M))
    ok(f"/metrics serves the {prefix}* series", len(series) > 10, f"{len(series)} series")
    for name in (f"{prefix}publish_decisions_total", f"{prefix}landings_total"):
        values = [float(v) for v in re.findall(rf"^{name}\{{[^}}]*\}} (\S+)", metrics, re.M)]
        ok(f"{name} counts something", sum(values) > 0, f"{len(values)} series, sum {sum(values)}")
    # What the chain mock answers the vault exporter (getPairs(), the CoinGecko stand-in's
    # USD prices) has to come out the other end, and a venue's `up` is its feed's own flag.
    def gauge(name, labels):
        found = re.findall(rf"^{prefix}{name}\{{{re.escape(labels)}\}} (\S+)", metrics, re.M)
        return float(found[0]) if found else None
    weth_vault = f'token="WETH",vault="{VAULT}"'
    price, balance, value = (gauge("token_price_usd", 'token="WETH"'), gauge("vault_balance", weth_vault),
                             gauge("vault_value_usd", weth_vault))
    ok("the vault's tokens are priced in USD through the CoinGecko stand-in", price == 2000.0, str(price))
    ok("a vault holding's USD value is its balance times that price",
       None not in (balance, value) and value == balance * 2000.0, f"balance {balance}, value {value}")
    ok("a venue's feed_up is read from its feed's own flag at scrape time",
       gauge("venue_feed_up", 'pair="WETH/USDC",venue="binance"') == 1.0)
    if custom:
        share = re.findall(rf'^{prefix}diagnostic\{{kind="tilted",name="base_share",pair="WETH/USDC"\}} (\S+)', metrics, re.M)
        ok("the tilted pricer's base_share diagnostic reaches /metrics", share and 0 <= float(share[0]) < 1e-6, str(share))

    width = max(len(name) for _, name, _ in results)
    for good, name, detail in results:
        print(f"  {'PASS' if good else 'FAIL'}  {name.ljust(width)}  {'' if good else detail}")
    passed = sum(good for good, _, _ in results)
    print(f"  {passed}/{len(results)} checks passed: {len(updates)} updates, "
          f"{len(distinct)} distinct transactions, blocks {mined_blocks[0]}-{mined_blocks[-1]}")
    return passed == len(results)


def compare(a_dir, b_dir):
    """Whether two binaries behaved the same: same report, same bytes, same log lines."""
    (_, wa, ra, ca), (_, wb, rb, cb) = load(a_dir), load(b_dir)
    results = []

    def blank(log):
        # Ack latency is the one thing that legitimately differs between two runs.
        return [re.sub(r"ack \d+ms", "ack Nms", line) for line in log.splitlines()]

    results.append((ca.split("--- stderr ---")[0] == cb.split("--- stderr ---")[0], "--check report identical"))
    ia, ib = [(m["block"], m["raw"]) for m in wa["mined"]], [(m["block"], m["raw"]) for m in wb["mined"]]
    results.append((ia == ib, f"all {len(ia)} included transactions byte-identical, signatures included"))
    sa = {e["tx"] for e in wa["events"] if e["kind"] == "update" and not e["cancel"]}
    sb = {e["tx"] for e in wb["events"] if e["kind"] == "update" and not e["cancel"]}
    results.append((sa == sb, f"the same {len(sa)} distinct transactions streamed"))
    # Pairs run as concurrent tasks, so their lines interleave differently from run to run;
    # each pair's own lines, in order, must match.
    for pair in ("USDC/USDT", "WETH/USDC"):
        pa = [line for line in blank(ra) if line.startswith(f"[{pair}]")]
        pb = [line for line in blank(rb) if line.startswith(f"[{pair}]")]
        results.append((pa == pb, f"[{pair}] log lines identical, in order ({len(pa)} lines)"))
    results.append((sorted(blank(ra)) == sorted(blank(rb)), "whole log: the same lines"))
    for good, name in results:
        print(f"  {'PASS' if good else 'FAIL'}  {name}")
    return all(good for good, _ in results)

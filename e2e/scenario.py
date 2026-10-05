"""Drives one binary through a scripted run against mocks.py and records what happened.

The script, in order: `--check`; then a live run of two pairs (USDC/USDT at a fixed price,
WETH/USDC priced from the Binance mock) quoting to two builders; three blocks; a price move;
two blocks; one builder killed; two blocks; a /metrics scrape; SIGINT. Everything the mocks
saw lands in <out>/world.json, the binary's output in <out>/check.out and <out>/run.out.

With `custom=True` the WETH/USDC pair is priced by the `tilted` kind instead (a fixed
half-spread, the mid tilted by the vault's base share), which `examples/tilted.rs`
registers: the library's custom path, vault read included, through the same script.
"""

import json
import os
import pathlib
import signal
import socket
import subprocess
import sys
import time
import urllib.request

from common import BUILDERS, KEYS

HERE = pathlib.Path(__file__).parent

# Long enough for the updater to see the new head (it polls), quote it, and hear both acks
# before the next block is mined, with a wide margin for a slow machine.
BLOCK_GAP_SECS = 2.5
START_PRICE = ("4000.00", "4000.20")
MOVED_PRICE = ("4100.00", "4100.20")

# All the binary inherits from the caller's shell. Its environment is built, not extended:
# every setting has an env var that beats the config's [settings] (cli.rs), so a shell's
# RPC_WS_URL would point the head watcher at a real node, a RECORD_DB_URL write e2e rows into
# a real Postgres, and a CHECK or MODE turn the run into another one.
INHERITED = ("PATH", "HOME", "TMPDIR")

# The scenario's own requests, to the mocks' control API and /metrics, with no proxy: urllib
# would otherwise send them to whatever the shell's http_proxy names, 127.0.0.1 or not.
LOCAL = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def free_ports(n):
    socks = [socket.socket() for _ in range(n)]
    for s in socks:
        s.bind(("127.0.0.1", 0))
    ports = [s.getsockname()[1] for s in socks]
    for s in socks:
        s.close()
    return ports


def pick_ports():
    """One set of ports; a comparison reuses it so both runs print the same URLs."""
    rpc, binance, metrics, *builders = free_ports(3 + len(BUILDERS))
    return {"rpc": rpc, "binance": binance, "metrics": metrics, "builders": builders}


# What the custom run's WETH/USDC pair is priced with; checks.py computes the expectation.
TILTED = {"half_spread": "0.0005", "tilt": "0.01"}


def config(ports, custom=False):
    pricing = f"""
[pairs.pricing]
kind        = "tilted"
half_spread = {TILTED['half_spread']}
tilt        = {TILTED['tilt']}
""" if custom else ""
    builders = "".join(f"""
[[builder]]
name = "{name}"
endpoint = "ws://127.0.0.1:{port}/ws/sendquoteupdate"
api_key = "{key}"
""" for (name, key), port in zip(BUILDERS, ports["builders"]))
    return f"""target = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"

[settings]
mode = "builder"
rpc_url = "http://127.0.0.1:{ports['rpc']}"
metrics_addr = "127.0.0.1:{ports['metrics']}"
binance_ws = "ws://127.0.0.1:{ports['binance']}/ws"

# Not a venue: where the vault exporter prices its tokens in USD, served by the chain mock.
[settings.endpoints]
coingecko = "http://127.0.0.1:{ports['rpc']}"

[[pairs]]
tokens  = ["0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "0xdAC17F958D2ee523a2206206994597C13D831ec7"]
mid     = "1.0001"
delta   = "0.0002"
key_env = "UPDATER_KEY_USDC_USDT"

[[pairs]]
tokens  = ["0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"]
symbol  = "ETHUSDC"
key_env = "UPDATER_KEY_WETH_USDC"
min_mid = "0.0001"
max_mid = "0.001"
""" + pricing + builders


class Mocks:
    def __init__(self, ports, out):
        self.url = f"http://127.0.0.1:{ports['rpc']}/control"
        cfg = {"rpc_port": ports["rpc"], "binance_port": ports["binance"],
               "prices": {"ETHUSDC": START_PRICE},
               "builders": [{"name": name, "api_key": key, "port": port}
                            for (name, key), port in zip(BUILDERS, ports["builders"])]}
        # The mocks keep the caller's environment, unlike the binary: it is how this
        # interpreter found aiohttp and websockets (a venv, PYTHONPATH), and they only listen.
        self.proc = subprocess.Popen([sys.executable, str(HERE / "mocks.py"), json.dumps(cfg)],
                                     cwd=HERE, stdout=subprocess.PIPE, text=True,
                                     stderr=open(out / "mocks.err", "w"))
        if self.proc.stdout.readline().strip() != "READY":
            raise SystemExit(f"the mocks did not start; see {out / 'mocks.err'}")

    def __call__(self, op, **query):
        url = f"{self.url}/{op}" + ("?" + "&".join(f"{k}={v}" for k, v in query.items()) if query else "")
        with LOCAL.open(urllib.request.Request(url, method="POST"), timeout=10) as r:
            return json.loads(r.read())

    def stop(self):
        self.proc.terminate()
        self.proc.wait(timeout=5)


def run(binary, out, ports, custom=False):
    """Runs the script against `binary`; returns the exit code the binary ended with."""
    out.mkdir(parents=True, exist_ok=True)
    (out / "config.toml").write_text(config(ports, custom))
    env = {**{k: os.environ[k] for k in INHERITED if k in os.environ}, **KEYS, "RUST_BACKTRACE": "1"}
    mocks = Mocks(ports, out)
    proc = None
    timeline = []

    def step(what, **fields):
        timeline.append({"t": time.time(), "step": what, **fields})

    def mine(n):
        for _ in range(n):
            step("mine", head=mocks("mine")["head"])
            time.sleep(BLOCK_GAP_SECS)

    try:
        check = subprocess.run([str(binary), "--config", "config.toml", "--check"], cwd=out,
                               env=env, capture_output=True, text=True, timeout=60)
        (out / "check.out").write_text(check.stdout + "\n--- stderr ---\n" + check.stderr)
        (out / "check.rc").write_text(str(check.returncode))

        proc = subprocess.Popen([str(binary), "--config", "config.toml"], cwd=out, env=env,
                                stdout=open(out / "run.out", "w"), stderr=subprocess.STDOUT)
        deadline = time.time() + 30
        while {e["builder"] for e in mocks("dump")["events"] if e["kind"] == "update"} != {n for n, _ in BUILDERS}:
            if time.time() > deadline or proc.poll() is not None:
                raise SystemExit(f"no update reached both builders within 30s; see {out / 'run.out'}")
            time.sleep(0.2)
        step("both builders quoting")
        time.sleep(2)
        mine(3)
        mocks("price", symbol="ETHUSDC", bid=MOVED_PRICE[0], ask=MOVED_PRICE[1])
        step("price moved")
        time.sleep(2)
        mine(2)
        mocks("kill-builder", name=BUILDERS[1][0])
        step("builder killed", builder=BUILDERS[1][0])
        time.sleep(2)
        mine(2)

        try:
            with LOCAL.open(f"http://127.0.0.1:{ports['metrics']}/metrics", timeout=5) as r:
                (out / "metrics.txt").write_text(r.read().decode())
        except OSError as e:
            (out / "metrics.txt").write_text(f"SCRAPE FAILED: {e}")

        proc.send_signal(signal.SIGINT)
        step("sigint")
        try:
            rc = proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()
            rc = "still running 20s after SIGINT"
        step("exited", rc=rc)
        time.sleep(0.5)  # the cancels are in flight when the process exits
        world = mocks("dump")
        world["timeline"] = timeline
        (out / "world.json").write_text(json.dumps(world, indent=1))
        return rc
    finally:
        if proc and proc.poll() is None:
            proc.kill()
        mocks.stop()

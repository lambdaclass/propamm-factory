"""End-to-end test of the quote updater binary against mocks of everything it talks to.

`make e2e` runs it. The binary quotes two pairs to two mock builders against a mock chain
and a mock Binance feed (mocks.py), through a fixed script (scenario.py), and checks.py
reads back everything the mocks saw: the signed bytes each builder was sent, decoded and
checked field by field; that each update lands and its nonces run in order; that a killed
builder leaves the other quoting; that SIGINT withdraws both quotes; and /metrics.

    python3 e2e/run.py --binary target/debug/quote-updater
    python3 e2e/run.py --binary target/release/quote-updater --baseline /path/to/old
    python3 e2e/run.py --binary target/debug/examples/tilted --custom

`--custom` prices WETH/USDC through the `tilted` kind, which `quote-updater/examples/tilted.rs`
registers, so `--binary` must be that example: the library's custom path end to end, the
vault read through the build context included (`make e2e-custom`).

`--baseline` runs a second binary through the same script on the same ports and compares:
the `--check` report, the signed bytes and every log line must match. The chain is
deterministic and the signatures are too (RFC 6979), so a refactor that changes nothing
shows as byte-identical, and anything it did change shows.

Needs Python 3.9+, aiohttp and websockets 13+ (`pip install -r e2e/requirements.txt`),
and foundry's `cast`. Talks to nothing beyond 127.0.0.1. Takes about 30s per binary.
"""

import argparse
import importlib
import pathlib
import shutil
import sys

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE))


def missing_prerequisites():
    missing = []
    if sys.version_info < (3, 9):
        missing.append(f"Python 3.9 or newer (this is {sys.version.split()[0]})")
    for module, need in (("aiohttp", None), ("websockets", 13)):
        try:
            mod = importlib.import_module(module)
            if need and int(mod.__version__.split(".")[0]) < need:
                missing.append(f"{module} >= {need} (found {mod.__version__})")
        except ImportError:
            missing.append(module)
    if not shutil.which("cast"):
        missing.append("foundry's `cast` on PATH (https://getfoundry.sh)")
    return missing


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--binary", required=True, type=pathlib.Path)
    parser.add_argument("--baseline", type=pathlib.Path, help="a second binary to compare against")
    parser.add_argument("--out", type=pathlib.Path, default=pathlib.Path("target/e2e"))
    parser.add_argument("--custom", action="store_true",
                        help="price WETH/USDC through the `tilted` kind of examples/tilted.rs")
    args = parser.parse_args()

    missing = missing_prerequisites()
    if missing:
        print("e2e needs:\n  - " + "\n  - ".join(missing) +
              "\nPython packages: pip install -r e2e/requirements.txt", file=sys.stderr)
        return 2
    for binary in filter(None, (args.binary, args.baseline)):
        if not binary.is_file():
            print(f"no binary at {binary}", file=sys.stderr)
            return 2

    import checks
    import scenario

    ports = scenario.pick_ports()
    runs = [("binary", args.binary)] + ([("baseline", args.baseline)] if args.baseline else [])
    passed = True
    for label, binary in runs:
        out = args.out / label
        print(f"{label}: {binary} (output in {out})")
        rc = scenario.run(binary.resolve(), out, ports, args.custom)
        print(f"  exited {rc}")
        passed &= checks.check(out, scenario.START_PRICE, scenario.MOVED_PRICE, args.custom)
    if args.baseline:
        print("compare: binary against baseline")
        passed &= checks.compare(args.out / "binary", args.out / "baseline")
    print("e2e: PASS" if passed else "e2e: FAIL")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())

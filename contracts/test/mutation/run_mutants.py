#!/usr/bin/env python3
"""Mutation run: plant one bug at a time in the contracts and require the tests to notice.

    python3 contracts/test/mutation/run_mutants.py            every mutant
    python3 contracts/test/mutation/run_mutants.py swap       the mutants whose name contains "swap"
    python3 contracts/test/mutation/run_mutants.py --list     their names

Each mutant below is one edit to a source file: a guard removed, a modifier dropped, an order
swapped. Where one bug takes two edits (a check made in two places), the mutant lists both.

A mutant is killed when `forge test` reports a failed test with it applied, and survives when
every test still passes, which means nothing in the suite depends on the line it broke. A
`forge test` that ends any other way (killed for memory on a small runner, a crash) is an
error, not a kill: it says nothing about the tests. The run exits 0 only if every mutant is
killed.

The sources are never edited in place. The run works on copies of `src/`, `test/` and
`foundry.toml` in a temporary directory, with `lib/` linked in, so an interrupted run leaves
the tree as it was.

A mutant's `old` text (each of them, if it has several) has to occur exactly once in its file and the mutated file has to
compile; either failing is an error in this list, not a kill. When a change to the contracts
breaks a mutant that way, fix the mutant here in the same change.
"""

import concurrent.futures
import json
import os
import pathlib
import queue
import shutil
import subprocess
import sys
import tempfile

CONTRACTS = pathlib.Path(__file__).resolve().parents[2]
PROPAMM = "src/PropAMM.sol"
FACTORY = "src/PropAMMFactory.sol"


def drop(text):
    """A mutant that deletes `text`."""
    return (text, "")


def swap_lines(first, second):
    """A mutant that runs `second` before `first`: two adjacent statements, reordered."""
    return (f"{first}\n{second}", f"{second}\n{first}")


def open_to_anyone(signature):
    """A mutant that drops `onlyOwner` from the function with this signature."""
    return (f"{signature} external onlyOwner {{", f"{signature} external {{")


I8 = " " * 8
I12 = " " * 12

# (name, file, (old, new)), or a list of (old, new) where one bug takes more than one edit.
MUTANTS = [
    # Owner-only functions, open to anyone.
    ("access: pause", PROPAMM, open_to_anyone("function pause()")),
    ("access: unpause", PROPAMM, open_to_anyone("function unpause()")),
    ("access: addPair", PROPAMM, open_to_anyone("function addPair(address tokenX, address tokenY, address vault)")),
    (
        "access: setPairVault",
        PROPAMM,
        open_to_anyone("function setPairVault(address tokenX, address tokenY, address vault)"),
    ),
    ("access: removePair", PROPAMM, open_to_anyone("function removePair(address tokenX, address tokenY)")),
    ("access: setOracle", PROPAMM, open_to_anyone("function setOracle(address newOracle)")),
    ("access: addUpdater", PROPAMM, open_to_anyone("function addUpdater(address updater)")),
    ("access: removeUpdater", PROPAMM, open_to_anyone("function removeUpdater(address updater)")),
    (
        "access: removeUpdaterFrom",
        PROPAMM,
        open_to_anyone("function removeUpdaterFrom(address registry, address updater)"),
    ),
    (
        "access: withdrawERC20",
        PROPAMM,
        open_to_anyone("function withdrawERC20(address token, address to, uint256 amount)"),
    ),
    ("access: upgrade", PROPAMM, ("internal override onlyOwner {}", "internal override {}")),
    ("access: disableCreation", FACTORY, open_to_anyone("function disableCreation()")),
    # swap's guards.
    ("swap: ignores its deadline", PROPAMM, drop(f"{I8}require(deadline >= block.timestamp, Expired());\n")),
    (
        "swap: ignores minAmountOut",
        PROPAMM,
        # Checked against the quote before anything moves and against the delivery after it.
        # Either check alone still refuses a normal token's shortfall, so the bug is both gone.
        [
            drop(f"{I8}require(realAmountOut >= minAmountOut, InsufficientOutput(minAmountOut, realAmountOut));\n"),
            drop(f"{I8}require(delivered >= minAmountOut, InsufficientOutput(minAmountOut, delivered));\n"),
        ],
    ),
    ("swap: takes a zero amountIn", PROPAMM, drop(f"{I8}require(amountIn != 0, ZeroAmountIn());\n")),
    ("swap: settles for zero output", PROPAMM, drop(f"{I8}require(realAmountOut != 0, ZeroAmountOut());\n")),
    (
        "swap: pays the zero address",
        PROPAMM,
        drop(f"{I8}require(recipient != address(0), InvalidRecipient(recipient));\n"),
    ),
    (
        "swap: pays the pair's own vault",
        PROPAMM,
        drop(f"{I8}require(recipient != vault, InvalidRecipient(recipient));\n"),
    ),
    (
        "swap: refuses the instance as recipient",
        PROPAMM,
        (
            f"{I8}require(recipient != address(0), InvalidRecipient(recipient));\n",
            f"{I8}require(recipient != address(0) && recipient != address(this), InvalidRecipient(recipient));\n",
        ),
    ),
    ("swap: runs while paused", PROPAMM, ("override nonReentrant whenNotPaused returns", "override nonReentrant returns")),
    ("swap: can be re-entered", PROPAMM, ("override nonReentrant whenNotPaused returns", "override whenNotPaused returns")),
    (
        "swap: logs Swapped before delivering",
        PROPAMM,
        (
            f"{I8}uint256 before = IERC20(tokenOut).balanceOf(recipient);\n"
            f"{I8}IERC20(tokenIn).safeTransfer(vault, amountIn);\n"
            f"{I8}IERC20(tokenOut).safeTransferFrom(vault, recipient, realAmountOut);\n"
            f"{I8}uint256 delivered = IERC20(tokenOut).balanceOf(recipient) - before;\n"
            f"{I8}require(delivered >= minAmountOut, InsufficientOutput(minAmountOut, delivered));\n\n"
            f"{I8}emit Swapped(msg.sender, tokenIn, tokenOut, amountIn, delivered, recipient);\n",
            f"{I8}uint256 before = IERC20(tokenOut).balanceOf(recipient);\n"
            f"{I8}emit Swapped(msg.sender, tokenIn, tokenOut, amountIn, realAmountOut, recipient);\n"
            f"{I8}IERC20(tokenIn).safeTransfer(vault, amountIn);\n"
            f"{I8}IERC20(tokenOut).safeTransferFrom(vault, recipient, realAmountOut);\n"
            f"{I8}uint256 delivered = IERC20(tokenOut).balanceOf(recipient) - before;\n"
            f"{I8}require(delivered >= minAmountOut, InsufficientOutput(minAmountOut, delivered));\n",
        ),
    ),
    (
        "swap: a short delivery passes minAmountOut",
        PROPAMM,
        drop(f"{I8}require(delivered >= minAmountOut, InsufficientOutput(minAmountOut, delivered));\n"),
    ),
    (
        "swap: reports the quote, not what arrived",
        PROPAMM,
        (
            f"{I8}emit Swapped(msg.sender, tokenIn, tokenOut, amountIn, delivered, recipient);\n\n"
            f"{I8}return delivered;",
            f"{I8}emit Swapped(msg.sender, tokenIn, tokenOut, amountIn, realAmountOut, recipient);\n\n"
            f"{I8}return realAmountOut;",
        ),
    ),
    # The pause, on the paths that read.
    (
        "pause: quote answers",
        PROPAMM,
        (f"{I8}whenNotPaused\n{I8}returns (uint256 amountOut)", f"{I8}returns (uint256 amountOut)"),
    ),
    (
        "pause: quoteFillable answers",
        PROPAMM,
        (
            f"{I8}whenNotPaused\n{I8}returns (uint256 fillableAmountIn, uint256 amountOut)",
            f"{I8}returns (uint256 fillableAmountIn, uint256 amountOut)",
        ),
    ),
    ("pause: isActive stays true", PROPAMM, drop(f"{I8}if (paused()) return false;\n")),
    # isActive, which makes quote's checks by hand so that it never reverts.
    ("isActive: answers for an unlisted pair", PROPAMM, drop(f"{I8}if (vault == address(0)) return false;\n")),
    (
        "isActive: does not read the registry's answer",
        PROPAMM,
        ("if (!ok || !_canPriceFrom(ret)) return false;", "if (!ok) return false;"),
    ),
    (
        "isActive: reads the answer of a registry that reverted",
        PROPAMM,
        ("if (!ok || !_canPriceFrom(ret)) return false;", "if (!_canPriceFrom(ret)) return false;"),
    ),
    (
        "isActive: an empty vault is active",
        PROPAMM,
        ("return ok && ret.length >= 32 && abi.decode(ret, (uint256)) != 0;", "return ok && ret.length >= 32;"),
    ),
    (
        "isActive: decodes a balance that is not there",
        PROPAMM,
        (
            "return ok && ret.length >= 32 && abi.decode(ret, (uint256)) != 0;",
            "return ok && abi.decode(ret, (uint256)) != 0;",
        ),
    ),
    (
        "isActive: decodes an answer too short for two slots",
        PROPAMM,
        drop(f"{I8}if (answer.length < 160) return false;\n"),
    ),
    (
        "isActive: takes the slots from any offset",
        PROPAMM,
        ("bool wellFormed = offset == 64 && count >= 2 &&", "bool wellFormed = count >= 2 &&"),
    ),
    (
        "isActive: takes fewer than two slots",
        PROPAMM,
        ("bool wellFormed = offset == 64 && count >= 2 &&", "bool wellFormed = offset == 64 &&"),
    ),
    (
        "isActive: takes slots the answer does not hold",
        PROPAMM,
        (" && count <= (answer.length - 96) / 32;", ";"),
    ),
    (
        "isActive: ignores the stamp",
        PROPAMM,
        ("return wellFormed && stamp == uint32(block.timestamp) &&", "return wellFormed &&"),
    ),
    (
        "isActive: compares the stamp's low 32 bits only",
        PROPAMM,
        (
            "return wellFormed && stamp == uint32(block.timestamp) &&",
            "return wellFormed && uint32(stamp) == uint32(block.timestamp) &&",
        ),
    ),
    (
        "isActive: takes a delta of one or more",
        PROPAMM,
        (" && delta < SPREAD_SCALE && mid != 0;", " && mid != 0;"),
    ),
    ("isActive: takes a zero mid", PROPAMM, (" && delta < SPREAD_SCALE && mid != 0;", " && delta < SPREAD_SCALE;")),
    # What a price has to be before it is quoted from.
    (
        "price: any past update is read",
        PROPAMM,
        (
            "oracle.getState(pairKey, uint32(block.timestamp), uint32(block.timestamp));",
            "oracle.getState(pairKey, 0, type(uint32).max);",
        ),
    ),
    (
        "price: the stamp is not checked",
        PROPAMM,
        drop(f"{I8}require(updatedAt == uint32(block.timestamp), StaleOracleData(pairKey, updatedAt));\n"),
    ),
    (
        "price: too few slots",
        PROPAMM,
        drop(f"{I8}require(slots.length >= 2, InsufficientOracleData(pairKey, slots.length));\n"),
    ),
    ("price: delta of one or more", PROPAMM, drop(f"{I8}require(p.delta < SPREAD_SCALE, SpreadTooWide(p.delta));\n")),
    ("price: zero mid", PROPAMM, drop(f"{I8}require(mid != 0, InvalidMid(pairKey));\n")),
    ("price: empty vault", PROPAMM, drop(f"{I8}require(p.vaultBalance != 0, EmptyVault(tokenOut));\n")),
    ("price: spread reaches one", PROPAMM, drop(f"{I8}require(spread < SPREAD_SCALE, SpreadTooWide(spread));\n")),
    (
        "price: more than the vault holds",
        PROPAMM,
        drop(
            f"{I8}require(amountOut <= p.vaultBalance, "
            "InsufficientVaultBalance(tokenOut, amountOut, p.vaultBalance));\n"
        ),
    ),
    (
        "price: no impact charged",
        PROPAMM,
        ("return Math.mulDiv(IMPACT_FACTOR, midAmountOut, vaultBalance);", "return 0;"),
    ),
    (
        "price: an unlisted pair",
        PROPAMM,
        drop(f"{I8}require(vault != address(0), UnsupportedPair(tokenX, tokenY));\n"),
    ),
    # quoteFillable's sizing.
    (
        "fillable: ignores the allowance",
        PROPAMM,
        (
            "Math.min(p.vaultBalance, IERC20(tokenOut).allowance(p.vault, address(this)));",
            "p.vaultBalance;",
        ),
    ),
    ("fillable: offers a fill that pays nothing", PROPAMM, drop(f"{I8}if (amountOut == 0) fillableAmountIn = 0;\n")),
    # Pair management.
    (
        "pairs: addPair takes a zero vault",
        PROPAMM,
        (
            f"{I8}require(vault != address(0), NoVault(token0, token1));\n{I8}require(token0.code.length > 0",
            f"{I8}require(token0.code.length > 0",
        ),
    ),
    (
        "pairs: addPair pairs a token with itself",
        PROPAMM,
        drop(f"{I8}require(token0 != token1, IdenticalTokens(token0));\n"),
    ),
    (
        "pairs: addPair lists a token0 without code",
        PROPAMM,
        drop(f"{I8}require(token0.code.length > 0, NotAToken(token0));\n"),
    ),
    (
        "pairs: addPair lists a token1 without code",
        PROPAMM,
        drop(f"{I8}require(token1.code.length > 0, NotAToken(token1));\n"),
    ),
    (
        "pairs: addPair lists a token0 with too many decimals",
        PROPAMM,
        drop(f"{I8}require(decimals0 <= MAX_TOKEN_DECIMALS, UnsupportedDecimals(token0, decimals0));\n"),
    ),
    (
        "pairs: addPair lists a token1 with too many decimals",
        PROPAMM,
        drop(f"{I8}require(decimals1 <= MAX_TOKEN_DECIMALS, UnsupportedDecimals(token1, decimals1));\n"),
    ),
    (
        "pairs: setPairVault takes a zero vault",
        PROPAMM,
        (
            f"{I8}require(vault != address(0), NoVault(token0, token1));\n"
            f"{I8}require(vault != pairVaults[pairKey]",
            f"{I8}require(vault != pairVaults[pairKey]",
        ),
    ),
    (
        "pairs: addPair lists a pair twice",
        PROPAMM,
        drop(f"{I8}require(pairVaults[pairKey] == address(0), PairAlreadyExists(token0, token1));\n"),
    ),
    (
        "pairs: setPairVault to the same vault",
        PROPAMM,
        drop(f"{I8}require(vault != pairVaults[pairKey], VaultUnchanged(token0, token1, vault));\n"),
    ),
    (
        "pairs: owner calls on an unlisted pair",
        PROPAMM,
        drop(f"{I8}require(pairVaults[pairKey] != address(0), UnsupportedPair(tokenX, tokenY));\n"),
    ),
    # The registry: which one, and which updater changes are real.
    (
        "oracle: initialize takes an address without code",
        PROPAMM,
        drop(f"{I8}require(oracle_.code.length > 0, InvalidOracle(oracle_));\n"),
    ),
    (
        "oracle: setOracle takes an address without code",
        PROPAMM,
        drop(f"{I8}require(newOracle.code.length > 0, InvalidOracle(newOracle));\n"),
    ),
    (
        "oracle: setOracle to the registry it already has",
        PROPAMM,
        drop(f"{I8}require(newOracle != address(oracle), OracleUnchanged(newOracle));\n"),
    ),
    (
        "updaters: a key the registry has is added again",
        PROPAMM,
        drop(
            f"{I8}require(!registry.isUpdater(address(this), updater), "
            "UpdaterAlreadyAuthorized(address(registry), updater));\n"
        ),
    ),
    (
        "updaters: a key the registry does not have is revoked",
        PROPAMM,
        drop(f"{I12}require(authorized, UpdaterNotAuthorized(address(registry), updater));\n"),
    ),
    (
        "updaters: revokes on an address without code",
        PROPAMM,
        drop(f"{I8}require(address(registry).code.length > 0, InvalidOracle(address(registry)));\n"),
    ),
    # Events: what is logged, and that it is logged before the call it announces.
    ("events: initialize omits the oracle", PROPAMM, drop(f"{I8}emit OracleChanged(oracle_);\n")),
    (
        "events: an added updater is not logged",
        PROPAMM,
        drop(f"{I8}emit UpdaterAuthorized(updater, address(registry));\n"),
    ),
    (
        "events: a revoked updater is not logged",
        PROPAMM,
        drop(f"{I8}emit UpdaterRevoked(updater, address(registry));\n"),
    ),
    (
        "events: an added updater is logged after the registry call",
        PROPAMM,
        swap_lines(f"{I8}emit UpdaterAuthorized(updater, address(registry));", f"{I8}registry.addUpdater(updater);"),
    ),
    (
        "events: a revoked updater is logged after the registry call",
        PROPAMM,
        swap_lines(f"{I8}emit UpdaterRevoked(updater, address(registry));", f"{I8}registry.removeUpdater(updater);"),
    ),
    (
        "events: withdrawERC20 logs after the transfer",
        PROPAMM,
        swap_lines(f"{I8}emit ERC20Withdrawn(token, to, amount);", f"{I8}IERC20(token).safeTransfer(to, amount);"),
    ),
    (
        "events: PropAMMCreated names the creator as owner",
        FACTORY,
        ("emit PropAMMCreated(propAmm, msg.sender, owner,", "emit PropAMMCreated(propAmm, msg.sender, msg.sender,"),
    ),
    # The factory.
    (
        "factory: creates after creation is disabled",
        FACTORY,
        (
            f"{I8}if (creationDisabled) revert CreationIsDisabled();\n{I8}propAmm = address(",
            f"{I8}propAmm = address(",
        ),
    ),
    (
        "factory: the salt leaves out the creator",
        FACTORY,
        ("abi.encode(creator, owner, oracle, updaters, pairs)", "abi.encode(owner, oracle, updaters, pairs)"),
    ),
]


def forge(args, cwd):
    return subprocess.run(["forge", *args], cwd=cwd, capture_output=True, text=True)


def how_it_ended(run):
    """`exited 1`, or the signal that stopped it, which is how a runner out of memory ends forge."""
    return f"was killed by signal {-run.returncode}" if run.returncode < 0 else f"exited {run.returncode}"


def said(run, limit):
    """The end of what a forge run printed, stderr included: compiler and toolchain errors go there."""
    return "\n".join(part.strip()[-limit:] for part in (run.stdout, run.stderr) if part.strip())


def failed_tests(report):
    """The tests a `forge test --json` report marks failed, or None if `report` is not one."""
    try:
        return [
            f"{suite} {test}"
            for suite, body in json.loads(report).items()
            for test, result in body["test_results"].items()
            if result["status"] == "Failure"
        ]
    except (ValueError, LookupError, TypeError, AttributeError):
        return None


def copy_of_the_contracts(into):
    """`src/`, `test/` and the config, with `lib/` linked: enough for forge to build and test."""
    for name in ("src", "test"):
        shutil.copytree(CONTRACTS / name, into / name)
    shutil.copy(CONTRACTS / "foundry.toml", into / "foundry.toml")
    os.symlink(CONTRACTS / "lib", into / "lib", target_is_directory=True)


def run_mutant(mutant, workdir, pristine):
    """Applies one mutant to the copy in `workdir`, judges it, and puts the file back."""
    name, file, edit = mutant
    source = mutated = pristine[file]
    for old, new in [edit] if isinstance(edit, tuple) else edit:
        if source.count(old) != 1:
            return name, "error", f"its text occurs {source.count(old)} times in {file}, not once"
        mutated = mutated.replace(old, new)
    target = workdir / file
    target.write_text(mutated)
    try:
        build = forge(["build"], workdir)
        if build.returncode != 0:
            return name, "error", f"it does not compile (`forge build` {how_it_ended(build)}):\n" + said(build, 1500)
        # A fixed seed, so a mutant only a fuzz test catches is caught every run or never. One
        # failed test settles the verdict, so the run stops at the first.
        tests = forge(["test", "--fuzz-seed", "1", "--fail-fast", "--json"], workdir)
        failed = failed_tests(tests.stdout)
        if tests.returncode == 0 and failed == []:
            return name, "survived", ""
        if tests.returncode != 0 and failed:
            return name, "killed", ""
        # Forge failed, not a test. Counted as a kill, this would hide a mutant that survives.
        report = "printed no test report" if failed is None else f"reported {len(failed)} failed tests"
        output = (tests.stderr.strip() or tests.stdout.strip())[-1500:]
        return name, "error", f"`forge test` {how_it_ended(tests)} and {report}" + (f":\n{output}" if output else "")
    finally:
        target.write_text(source)


def main(argv):
    wanted = [arg for arg in argv if not arg.startswith("--")]
    mutants = [m for m in MUTANTS if all(word in m[0] for word in wanted)]
    if "--list" in argv:
        print("\n".join(m[0] for m in mutants))
        return 0
    if not mutants:
        print(f"no mutant matches {' '.join(wanted)!r}", file=sys.stderr)
        return 2

    pristine = {file: (CONTRACTS / file).read_text() for file in (PROPAMM, FACTORY)}
    jobs = max(1, min(len(mutants), os.cpu_count() or 1, 4))

    with tempfile.TemporaryDirectory(prefix="propamm-mutants-") as tmp:
        first = pathlib.Path(tmp) / "0"
        first.mkdir()
        copy_of_the_contracts(first)
        # Unmutated, the suite has to pass: otherwise every mutant would look killed.
        baseline = forge(["test", "--fuzz-seed", "1"], first)
        if baseline.returncode != 0:
            print(
                f"the tests fail before any mutant is applied (`forge test` {how_it_ended(baseline)}):\n"
                + said(baseline, 3000),
                file=sys.stderr,
            )
            return 2

        # One copy per worker, each starting from the first one's build.
        workdirs = queue.SimpleQueue()
        workdirs.put(first)
        for i in range(1, jobs):
            workdir = pathlib.Path(tmp) / str(i)
            shutil.copytree(first, workdir, symlinks=True)
            workdirs.put(workdir)

        def judge(mutant):
            workdir = workdirs.get()
            try:
                return run_mutant(mutant, workdir, pristine)
            finally:
                workdirs.put(workdir)

        with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
            results = list(pool.map(judge, mutants))

    for name, verdict, detail in results:
        print(f"{verdict:>8}  {name}" + (f"\n          {detail}" if detail else ""))
    survived = [name for name, verdict, _ in results if verdict == "survived"]
    errors = [name for name, verdict, _ in results if verdict == "error"]
    print(f"\n{len(results) - len(survived) - len(errors)} of {len(results)} mutants killed")
    if errors:
        print(f"{len(errors)} could not be judged: fix them in {pathlib.Path(__file__).name}", file=sys.stderr)
    if survived:
        print(f"{len(survived)} survived: no test fails with these bugs planted", file=sys.stderr)
    return 1 if survived or errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

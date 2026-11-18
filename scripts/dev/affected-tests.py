#!/usr/bin/env python3
"""Print (or run) the tests that cover the files changed on this branch.

Fast local loop: run only what a change can break, then let CI run the full
suite. Paths come from `git diff --name-only <base>...HEAD` plus uncommitted
and untracked files, so it works before and after committing.

    scripts/dev/affected-tests.py              # print the plan (base origin/main)
    scripts/dev/affected-tests.py --run        # run it, stop at the first failure
    scripts/dev/affected-tests.py --base main  # diff against another base
    scripts/dev/affected-tests.py --self-test  # check the path -> command rules

With --run each command goes through $HEAVY (a load-gated lock wrapper) when
that variable is set.

A byte-moving change (any path the wire-format gate watches) also gets the
conformance multi-format run in both fold modes and a pointer to the golden
sweep, because CI cannot restamp goldens. Everything else is left to CI.
"""
from __future__ import annotations

import argparse
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

ROOT = Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip())

GATES = [
    "bash scripts/lint-no-silent-skips.sh",
    "node conformance/scripts/check-golden-provenance.mjs --base {base}",
    "pnpm run -s wire-format-audit",
]

# Paths whose edits can move emitted bytes (mirrors the wire-format gate's
# intent: codegen, stack lowering, emit, ANF lowering, optimizers, SDK
# serializers/interpreters).
BYTE_MOVING = re.compile(
    r"^(packages/runar-compiler/src/(passes/(0[4-6]-|.*codegen|stateful-scaffold)|optimizer/)"
    r"|compilers/[^/]+/.*(codegen|stack|emit|anf_lower|AnfLower|StackLower|Emit|optimizer|peephole|constant_fold)"
    r"|packages/runar-(sdk|go|rs|py|rb|zig|java)/.*(state|anf.interpreter|anf_interpreter|AnfInterpreter|serializ|envelope|canonical))",
    re.IGNORECASE,
)
# Test sources never move emitted bytes.
TEST_PATH = re.compile(r"(/__tests__/|/tests?/|/spec/|_test\.(go|zig|rs)$|Test\.java$|\.test\.ts$|_spec\.rb$)")


def changed_files(base: str) -> list[str]:
    def lines(*cmd: str) -> list[str]:
        out = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True)
        return [l for l in out.stdout.splitlines() if l.strip()]

    files = set(lines("git", "diff", "--name-only", f"{base}...HEAD"))
    files |= set(lines("git", "diff", "--name-only", "HEAD"))
    files |= set(lines("git", "ls-files", "--others", "--exclude-standard"))
    return sorted(files)


def plan(files: list[str], base: str) -> tuple[list[str], list[str]]:
    """Return (commands, notes) for a list of repo-relative paths."""
    cmds: list[str] = []
    notes: list[str] = []

    def add(c: str) -> None:
        if c not in cmds:
            cmds.append(c)

    def under(prefix: str) -> list[str]:
        return [f for f in files if f.startswith(prefix)]

    # --- TypeScript: vitest's module graph picks the affected test files.
    ts_roots = ("packages/", "conformance/", "tests/", "examples/ts/", "examples/sol/",
                "examples/move/", "vitest.config.ts", "package.json", "pnpm-lock.yaml")
    if any(f.startswith(ts_roots) and not f.startswith(_NATIVE_PKGS) for f in files):
        add("pnpm run build")
        add(f"npx vitest run --changed {base}")
    # Tests that read fixtures through fs are invisible to the module graph.
    if under("conformance/negatives/"):
        add("npx vitest run conformance/negatives")
    if under("conformance/anf-interpreter/"):
        add("npx vitest run conformance/anf-interpreter")
    if under("conformance/sdk-envelope/"):
        add("npx vitest run conformance/sdk-envelope")
        notes.append("sdk-envelope fixtures changed: also run each SDK's envelope interop test")

    # --- Native compilers.
    go_pkgs = sorted({f.split("/")[2] for f in under("compilers/go/") if f.count("/") >= 3})
    if under("compilers/go/"):
        add("cd compilers/go && go build -o runar-go . && go test "
            + (" ".join(f"./{p}/..." for p in go_pkgs) if go_pkgs else "."))
    if under("compilers/rust/"):
        add(_only_tests(under("compilers/rust/"), r"^compilers/rust/tests/([^/]+)\.rs$",
                        "cd compilers/rust && cargo build --release -q && cargo test --test {}",
                        "cd compilers/rust && cargo build --release -q && cargo test"))
    if under("compilers/python/"):
        add(_only_tests(under("compilers/python/"), r"^compilers/python/(tests/test_[^/]+\.py)$",
                        "cd compilers/python && python3 -m pytest -q {}",
                        "cd compilers/python && python3 -m pytest -q", join=True))
    if under("compilers/ruby/"):
        add(_only_tests(under("compilers/ruby/"), r"^compilers/ruby/(test/test_[^/]+\.rb)$",
                        "cd compilers/ruby && ruby -Ilib -Itest {}",
                        "cd compilers/ruby && rake test", join=False))
    if under("compilers/zig/"):
        add("cd compilers/zig && zig build -Doptimize=ReleaseSafe && zig build test --summary failures")
    if under("compilers/java/"):
        add(_only_tests(under("compilers/java/"), r"^compilers/java/src/test/java/.*/([A-Za-z0-9_]+)\.java$",
                        "cd compilers/java && ./gradlew jar test --no-daemon -q --tests '*{}'",
                        "cd compilers/java && ./gradlew jar test --no-daemon -q", join=False))

    # --- Native SDK packages.
    if under("packages/runar-go/"):
        add("cd packages/runar-go && go test ./...")
    if under("packages/runar-rs/"):
        add("cd packages/runar-rs && cargo test")
    if under("packages/runar-py/"):
        add(_only_tests(under("packages/runar-py/"), r"^packages/runar-py/(tests/test_[^/]+\.py)$",
                        "cd packages/runar-py && python3 -m pytest -q {}",
                        "cd packages/runar-py && python3 -m pytest -q", join=True))
    if under("packages/runar-rb/"):
        add(_only_tests(under("packages/runar-rb/"), r"^packages/runar-rb/(spec/.+_spec\.rb)$",
                        "cd packages/runar-rb && bundle exec rspec {}",
                        "cd packages/runar-rb && bundle exec rspec", join=True))
    if under("packages/runar-zig/"):
        add("cd packages/runar-zig && zig build test --summary failures")
    if under("packages/runar-java/"):
        add("cd packages/runar-java && ./gradlew test --no-daemon -q")

    # --- Native examples.
    for lang, cmd in (("go", "cd examples/go && go test ./..."),
                      ("rust", "cd examples/rust && cargo test"),
                      ("python", "cd examples/python && PYTHONPATH=../../packages/runar-py python3 -m pytest -q"),
                      ("zig", "cd examples/zig && zig build test"),
                      ("java", "cd examples/java && ./gradlew test --no-daemon -q")):
        if under(f"examples/{lang}/"):
            add(cmd)

    # --- Things that need more than a test command.
    for lang in ("go", "ts", "rust", "python", "ruby", "zig", "java"):
        if under(f"integration/{lang}/"):
            notes.append(f"integration/{lang} changed: needs a regtest node (cd integration && ./regtest.sh start); "
                         "run only the changed test files, CI runs the rest")
    if under("runar-verification/"):
        notes.append("runar-verification changed: lake build only the changed modules; "
                     "PipelineGolden fingerprint procedure if RunarVerification/** moved")
    if under("conformance/tests/"):
        fx = sorted({f.split("/")[2] for f in under("conformance/tests/") if f.count("/") >= 3})
        notes.append("conformance fixtures changed (" + ", ".join(fx) + "): --multi-format has no filter, "
                     "so the per-fixture golden runs below cover them; CI runs the full multi-format matrix")
        for f in fx:  # --filter is a single case-insensitive substring match
            add(f"conformance/node_modules/.bin/tsx conformance/runner/index.ts --tests-dir conformance/tests --filter {f}")

    byte_moving = [f for f in files if BYTE_MOVING.search(f) and not TEST_PATH.search(f)]
    if byte_moving:
        notes.append("BYTE-MOVING paths changed (" + ", ".join(byte_moving[:6])
                     + (" ..." if len(byte_moving) > 6 else "")
                     + "): if any emitted byte moves, follow the golden sweep checklist "
                       "(memory project_golden_sweep_checklist) - CI cannot restamp")
        add("RUNAR_DISABLE_CONSTANT_FOLDING=1 conformance/node_modules/.bin/tsx conformance/runner/index.ts "
            "--tests-dir conformance/tests --multi-format")
        add("RUNAR_DISABLE_CONSTANT_FOLDING=0 conformance/node_modules/.bin/tsx conformance/runner/index.ts "
            "--tests-dir conformance/tests --multi-format")

    for g in GATES:
        add(g.format(base=base))
    return cmds, notes


_NATIVE_PKGS = tuple(f"packages/runar-{t}/" for t in ("go", "rs", "py", "rb", "zig", "java"))


def _only_tests(paths: list[str], test_re: str, each: str, full: str, join: bool = False) -> str:
    """If every changed path is a test file, run just those; else the full suite."""
    m = [re.match(test_re, p) for p in paths]
    if paths and all(m):
        names = [x.group(1) for x in m]
        if join:
            return each.format(" ".join(names))
        return " && ".join(each.format(n) for n in names)
    return full


def self_test() -> int:
    cases = {
        ("docs/test-skips.md",): {"bash scripts/lint-no-silent-skips.sh"},
        ("compilers/python/tests/test_x.py",): {"cd compilers/python && python3 -m pytest -q tests/test_x.py"},
        ("compilers/python/runar_compiler/frontend/typecheck.py",): {"cd compilers/python && python3 -m pytest -q"},
        ("compilers/go/frontend/validator.go",): {"cd compilers/go && go build -o runar-go . && go test ./frontend/..."},
        ("compilers/rust/tests/gk_frontend_tests.rs",):
            {"cd compilers/rust && cargo build --release -q && cargo test --test gk_frontend_tests"},
        ("packages/runar-sdk/src/contract.ts",): {"npx vitest run --changed origin/main"},
        ("conformance/negatives/N540-x.runar.ts",): {"npx vitest run conformance/negatives"},
        ("compilers/zig/src/passes/stack_lower.zig",):
            {"RUNAR_DISABLE_CONSTANT_FOLDING=0 conformance/node_modules/.bin/tsx conformance/runner/index.ts "
             "--tests-dir conformance/tests --multi-format"},
        ("packages/runar-go/sdk_contract.go",): {"cd packages/runar-go && go test ./..."},
        ("conformance/tests/stateful/expected-script.hex",):
            {"conformance/node_modules/.bin/tsx conformance/runner/index.ts --tests-dir conformance/tests --filter stateful"},
    }
    bad = 0
    for paths, must in cases.items():
        cmds, _ = plan(list(paths), "origin/main")
        missing = must - set(cmds)
        if missing:
            bad += 1
            print(f"FAIL {paths}: missing {missing}\n  got {cmds}")
    # A docs-only change must not trigger any suite beyond the gates.
    cmds, _ = plan(["docs/README.md"], "origin/main")
    if [c for c in cmds if c not in {g.format(base='origin/main') for g in GATES}]:
        bad += 1
        print(f"FAIL docs-only change ran suites: {cmds}")
    # A test file next to a codegen module is not byte-moving.
    cmds, _ = plan(["compilers/java/src/test/java/runar/compiler/passes/StackLowerTest.java"], "origin/main")
    if any("--multi-format" in c for c in cmds):
        bad += 1
        print(f"FAIL test-only change flagged byte-moving: {cmds}")
    print("self-test:", "OK" if not bad else f"{bad} failure(s)")
    return 1 if bad else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", default="origin/main")
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        return self_test()
    files = changed_files(a.base)
    if not files:
        print("no changed files")
        return 0
    cmds, notes = plan(files, a.base)
    print(f"{len(files)} changed file(s) vs {a.base}")
    for n in notes:
        print("note:", n)
    for c in cmds:
        print("  $", c)
    if not a.run:
        return 0
    heavy = os.environ.get("HEAVY")
    for c in cmds:
        print(f"\n>>> {c}", flush=True)
        argv = ([heavy] if heavy else []) + ["bash", "-c", c]
        rc = subprocess.call(argv, cwd=ROOT)
        if rc:
            print(f"FAILED (exit {rc}): {c}")
            return rc
    print("\nall affected tests passed; CI runs the full suite")
    return 0


if __name__ == "__main__":
    sys.exit(main())

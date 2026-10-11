"""Byte-identical golden diff harness for the Python compiler.

For every directory under ``conformance/tests/``, this test:
  1. Locates the Python-format source file (``*.runar.py``)
  2. Invokes the Python compiler via its module entry point
  3. Canonicalizes the ANF IR JSON (sort keys, strip ``sourceLoc``, 2-space indent)
  4. Asserts byte-for-byte equality against ``expected-ir.json`` and ``expected-script.hex``

The canonicalization matches ``conformance/runner/runner.ts::canonicalizeJson``.

Failures are collected and the first 5 are reported with concrete diffs; the
test only asserts after every fixture has been processed so the surface area
of real conformance gaps is fully visible in one run.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Optional

import pytest


HERE = Path(__file__).resolve().parent
PYTHON_COMPILER_DIR = HERE.parent
CONFORMANCE_DIR = PYTHON_COMPILER_DIR.parent.parent / "conformance" / "tests"


def _find_python_source(test_dir: Path) -> Optional[Path]:
    """Resolve the Python-format source file for a conformance fixture.

    Mirrors the TS runner (`conformance/runner/runner.ts`):
      1. If ``source.json`` exists and has a ``.runar.py`` entry in ``sources``,
         resolve it relative to the fixture directory.
      2. Otherwise fall back to the first ``*.runar.py`` file in the fixture dir.

    F-323: a ``source.json`` that exists but is unreadable or malformed used to
    be swallowed (``except (json.JSONDecodeError, OSError): pass``) and fall
    through to the glob as if the config had never existed. That misreports a
    broken config as a plain "no source found" outcome and can mask a real
    config error behind a fixture that happens to resolve via the glob
    fallback anyway. Let it raise -- same fail-closed approach as F-225 (TS)
    and F-264 (Ruby) took for the identical pattern in their harnesses.
    """
    config_path = test_dir / "source.json"
    if config_path.exists():
        cfg = json.loads(config_path.read_text(encoding="utf-8"))
        rel = (cfg.get("sources") or {}).get(".runar.py")
        if isinstance(rel, str):
            resolved = (test_dir / rel).resolve()
            if resolved.exists():
                return resolved

    for entry in sorted(test_dir.iterdir()):
        if entry.is_file() and entry.name.endswith(".runar.py"):
            return entry
    return None


def _canonicalize_value(v):
    if isinstance(v, dict):
        out = {}
        for k in sorted(v.keys()):
            if k == "sourceLoc":
                continue
            out[k] = _canonicalize_value(v[k])
        return out
    if isinstance(v, list):
        return [_canonicalize_value(x) for x in v]
    return v


def _canonicalize_json(s: str) -> str:
    """Parse JSON, strip sourceLoc, sort keys, re-serialize with 2-space indent."""
    parsed = json.loads(s)
    return json.dumps(_canonicalize_value(parsed), indent=2, ensure_ascii=False)


def _run_compiler(source_path: Path, flags: list[str]) -> subprocess.CompletedProcess:
    """Invoke the Python compiler module in the compilers/python directory."""
    env = os.environ.copy()
    cmd = [sys.executable, "-m", "runar_compiler", "--source", str(source_path), *flags]
    return subprocess.run(
        cmd,
        cwd=str(PYTHON_COMPILER_DIR),
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
    )


def _discover_fixtures() -> list[Path]:
    return sorted(p for p in CONFORMANCE_DIR.iterdir() if p.is_dir())


def _compare_goldens(
    name: str, test_dir: Path, actual_ir: str, actual_hex: str
) -> Optional[tuple[str, str, str, str]]:
    """Compare a fixture's actual (already-canonicalized) IR/hex against its
    checked-in ``expected-ir.json`` / ``expected-script.hex``.

    F-323: this used to be inline, gated behind ``if expected_ir_path.exists():``
    / ``if expected_hex_path.exists():`` -- a fixture whose golden file was
    missing (e.g. accidentally deleted) skipped the comparison entirely and
    fell through to ``passed``, with zero bytes actually checked. A missing
    or unreadable golden is now a failure (kind ``missing-golden-ir`` /
    ``missing-golden-hex``), mirroring the Go harness's ``compareGoldens``
    (F-280).

    Returns ``None`` when both goldens are present and byte-identical to the
    actual output, else a ``(name, kind, expected, actual)`` failure tuple.
    """
    expected_ir_path = test_dir / "expected-ir.json"
    if not expected_ir_path.exists():
        return (name, "missing-golden-ir", "", f"expected-ir.json not found for fixture '{name}'")
    try:
        expected_ir = _canonicalize_json(expected_ir_path.read_text(encoding="utf-8"))
    except Exception as e:
        return (name, "canonicalize-expected-ir", "", str(e))
    if actual_ir != expected_ir:
        return (name, "ir-mismatch", expected_ir, actual_ir)

    expected_hex_path = test_dir / "expected-script.hex"
    if not expected_hex_path.exists():
        return (name, "missing-golden-hex", "", f"expected-script.hex not found for fixture '{name}'")
    expected_hex = "".join(expected_hex_path.read_text(encoding="utf-8").split()).lower()
    if actual_hex != expected_hex:
        return (name, "script-mismatch", expected_hex, actual_hex)

    return None


def _scan_fixtures(dirs: list[Path]) -> dict[str, list]:
    """Walk ``dirs`` (conformance fixture directories) and classify each one.

    F-323: a fixture with no resolvable ``.runar.py`` source used to go into a
    separate ``missing`` bucket that was printed in the summary but never
    asserted on -- the test harness could report green while having checked
    nothing at all for that fixture. A missing source is now a failure (kind
    ``missing-source``), the same classification Ruby's ``scan_fixtures``
    (F-151) uses.

    Returns ``{"passed": [name, ...], "failures": [(name, kind, expected,
    actual), ...]}``.
    """
    passed: list[str] = []
    failures: list[tuple[str, str, str, str]] = []

    for test_dir in dirs:
        name = test_dir.name
        source = _find_python_source(test_dir)
        if source is None:
            failures.append((name, "missing-source", "", f"no .runar.py source found for fixture '{name}'"))
            continue

        # Step 1: IR
        ir_proc = _run_compiler(source, ["--emit-ir", "--disable-constant-folding"])
        if ir_proc.returncode != 0:
            failures.append((name, "compile-ir", "", (ir_proc.stderr or ir_proc.stdout).strip()))
            continue
        actual_ir_raw = ir_proc.stdout

        # Step 2: script hex
        hex_proc = _run_compiler(source, ["--hex", "--disable-constant-folding"])
        if hex_proc.returncode != 0:
            failures.append((name, "compile-hex", "", (hex_proc.stderr or hex_proc.stdout).strip()))
            continue
        actual_hex = "".join(hex_proc.stdout.split()).lower()

        # Step 3: canonicalize actual IR, then compare both goldens
        try:
            actual_ir = _canonicalize_json(actual_ir_raw)
        except Exception as e:
            failures.append((name, "canonicalize-actual-ir", "", f"{e}\n-- raw --\n{actual_ir_raw[:500]}"))
            continue

        fail = _compare_goldens(name, test_dir, actual_ir, actual_hex)
        if fail is not None:
            failures.append(fail)
            continue

        passed.append(name)

    return {"passed": passed, "failures": failures}


def _short_diff(expected: str, actual: str, limit: int = 12) -> str:
    exp_lines = expected.splitlines()
    act_lines = actual.splitlines()
    out: list[str] = []
    shown = 0
    for i in range(max(len(exp_lines), len(act_lines))):
        e = exp_lines[i] if i < len(exp_lines) else "<EOF>"
        a = act_lines[i] if i < len(act_lines) else "<EOF>"
        if e != a:
            out.append(f"    line {i + 1}:")
            out.append(f"      - expected: {e}")
            out.append(f"      + actual:   {a}")
            shown += 1
            if shown >= limit:
                out.append("    ... (truncated)")
                break
    if not out:
        out.append("    (strings differ but no line diff; likely trailing whitespace)")
    return "\n".join(out)


def test_conformance_goldens_python(capsys):
    assert CONFORMANCE_DIR.is_dir(), f"missing conformance dir: {CONFORMANCE_DIR}"
    dirs = _discover_fixtures()

    result = _scan_fixtures(dirs)
    passed: list[str] = result["passed"]
    failures: list[tuple[str, str, str, str]] = result["failures"]

    total = len(dirs)
    lines: list[str] = []
    lines.append(
        f"\n=== Python conformance-goldens summary: {len(passed)} pass / "
        f"{len(failures)} fail (of {total} fixtures) ==="
    )
    for (name, kind, expected, actual) in failures[:5]:
        lines.append(f"\n--- FAIL: {name} ({kind}) ---")
        if kind == "ir-mismatch":
            lines.append(f"  expected {len(expected)} chars, actual {len(actual)} chars:")
            lines.append(_short_diff(expected, actual))
        elif kind == "script-mismatch":
            min_len = min(len(expected), len(actual))
            first_diff = min_len
            for i in range(min_len):
                if expected[i] != actual[i]:
                    first_diff = i
                    break
            lo = max(0, first_diff - 20)
            exp_hi = min(first_diff + 20, len(expected))
            act_hi = min(first_diff + 20, len(actual))
            lines.append(
                f"  expected {len(expected)} hex chars, actual {len(actual)} hex chars"
            )
            lines.append(
                f"  first diff at hex offset {first_diff} (byte {first_diff // 2})"
            )
            lines.append(f"  expected: ...{expected[lo:exp_hi]}...")
            lines.append(f"  actual:   ...{actual[lo:act_hi]}...")
        else:
            # compile error or canonicalization error
            lines.append(f"  {actual}")
    if len(failures) > 5:
        lines.append(f"\n... and {len(failures) - 5} more failures:")
        for (name, _kind, _e, _a) in failures[5:]:
            lines.append(f"  - {name}")

    print("\n".join(lines))

    assert not failures, (
        f"{len(failures)} of {total} fixtures failed conformance-goldens; "
        f"see captured stdout for details"
    )


# ----------------------------------------------------------------------
# F-323: the Python golden harness had three ways to report green on a
# fixture it never checked:
#   (1) a fixture with no resolvable .runar.py source went into a `missing`
#       bucket that was printed but never asserted on;
#   (2) a missing expected-ir.json / expected-script.hex skipped the
#       comparison entirely and fell through to `passed`;
#   (3) a malformed/unreadable source.json was swallowed and fell through to
#       the glob fallback as if no config existed.
# Each is reproduced below against a synthetic, throwaway fixture directory
# (never against the real conformance corpus) and proven fixed.
# ----------------------------------------------------------------------


def test_find_python_source_raises_on_malformed_source_json(tmp_path):
    """What this proves: a malformed `source.json` now propagates a
    `json.JSONDecodeError` out of `_find_python_source` instead of being
    swallowed and falling through to the `*.runar.py` glob fallback.

    What this does not prove: anything about the TS runner's own
    `loadSourceConfig`/`readFixtureCompilerAllowlist` (fixed separately for
    the collection path in F-225) or the real conformance corpus, which
    contains no malformed `source.json` today.
    """
    fixture_dir = tmp_path / "f323-malformed-source-json"
    fixture_dir.mkdir()
    (fixture_dir / "source.json").write_text("{not valid json", encoding="utf-8")
    # Deliberately no *.runar.py file either, so before the fix this would
    # resolve to None (swallow -> empty glob) instead of raising.

    with pytest.raises(json.JSONDecodeError):
        _find_python_source(fixture_dir)


def test_compare_goldens_missing_ir_is_failure(tmp_path):
    """What this proves: `_compare_goldens` treats a missing
    `expected-ir.json` as a failure (kind `missing-golden-ir`), not as
    "nothing to compare against, mark it passed".

    What this does not prove: that `_scan_fixtures` wires this in for a real
    compiled fixture end-to-end (that's covered by
    `test_conformance_goldens_python` passing against the real corpus, where
    every fixture ships both goldens today).
    """
    fixture_dir = tmp_path / "f323-missing-ir-golden"
    fixture_dir.mkdir()
    (fixture_dir / "expected-script.hex").write_text("deadbeef", encoding="utf-8")
    # expected-ir.json deliberately absent.

    result = _compare_goldens("fake-fixture", fixture_dir, '{"anything": true}', "deadbeef")

    assert result is not None, (
        "_compare_goldens returned None (treated missing expected-ir.json as a pass); "
        "want a failure with kind=missing-golden-ir"
    )
    name, kind, _expected, _actual = result
    assert kind == "missing-golden-ir", f"got failure kind {kind!r}, want 'missing-golden-ir'"


def test_compare_goldens_missing_hex_is_failure(tmp_path):
    """What this proves: `_compare_goldens` treats a missing
    `expected-script.hex` as a failure (kind `missing-golden-hex`), isolated
    from the IR-missing path above by giving it a matching IR golden so the
    IR comparison passes first.

    What this does not prove: the hex comparison logic itself when the
    golden IS present (covered elsewhere by the real-corpus run).
    """
    fixture_dir = tmp_path / "f323-missing-hex-golden"
    fixture_dir.mkdir()
    ir_json = '{"anything": true}'
    (fixture_dir / "expected-ir.json").write_text(ir_json, encoding="utf-8")
    actual_ir = _canonicalize_json(ir_json)
    # expected-script.hex deliberately absent.

    result = _compare_goldens("fake-fixture", fixture_dir, actual_ir, "deadbeef")

    assert result is not None, (
        "_compare_goldens returned None (treated missing expected-script.hex as a pass); "
        "want a failure with kind=missing-golden-hex"
    )
    name, kind, _expected, _actual = result
    assert kind == "missing-golden-hex", f"got failure kind {kind!r}, want 'missing-golden-hex'"


def test_scan_fixtures_fails_on_missing_source(tmp_path):
    """What this proves: `_scan_fixtures` classifies a fixture with no
    resolvable `.runar.py` source as a FAILURE (kind `missing-source`) in
    its returned `failures` list, not as a silently-unasserted `missing`
    bucket that the caller can ignore.

    What this does not prove: that the real conformance corpus contains such
    a fixture today -- it does not (every fixture ships a `.runar.py`
    source); this is a synthetic, throwaway fixture directory.
    """
    fixture_dir = tmp_path / "f323-no-source"
    fixture_dir.mkdir()
    # No source.json, no *.runar.py file.

    result = _scan_fixtures([fixture_dir])

    assert result["passed"] == []
    kinds = [kind for (_name, kind, _e, _a) in result["failures"]]
    assert "missing-source" in kinds, (
        f"expected a 'missing-source' failure, got failures={result['failures']!r}"
    )

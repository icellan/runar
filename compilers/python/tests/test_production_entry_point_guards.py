"""R-024: the frontend guards must hold on EVERY production entry point.

``parser_dispatch.parse_source`` carries two guards:

  * the 4 MiB ``MAX_SOURCE_BYTES`` DoS bound (``assert_source_bytes_under_limit``)
  * the fail-closed ``@sighash`` / ``@embedAlways`` directive guard for the
    eight non-TS surfaces whose parsers ignore comments

Both were previously reachable only through ``parse_source``, which no
production module imports — the shipping path used a second, unguarded
nine-way dispatcher (``compiler._parse_source``). These tests pin every
production entry point instead of the dispatcher, so a future duplicate
cannot silently reopen the hole.

Each entry point is exercised three ways:
  * oversize source            -> must be REJECTED
  * non-TS source w/ @sighash  -> must be REJECTED
  * ordinary source (control)  -> must still COMPILE
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import pytest

from runar_compiler.compiler import (
    compile_from_source,
    compile_from_source_str_with_result,
    compile_from_source_with_result,
    compile_source_to_ir,
)
from runar_compiler.frontend.input_limits import MAX_SOURCE_BYTES

PYTHON_COMPILER_DIR = Path(__file__).resolve().parent.parent

CONTROL_SOURCE = """pragma runar ^0.1.0;

contract GuardCounter is StatefulSmartContract {
    bigint count;

    constructor(bigint _count) {
        count = _count;
    }

    function bump(bigint n) public {
        this.count = this.count + n;
    }
}
"""

SOURCE_NAME = "GuardCounter.runar.sol"

# One byte over MAX_SOURCE_BYTES. The padding is leading whitespace so the
# payload stays a syntactically valid Solidity-surface contract -- proving the
# rejection comes from the size guard and not from a parse error.
OVERSIZE_SOURCE = (
    " " * (MAX_SOURCE_BYTES + 1 - len(CONTROL_SOURCE.encode("utf-8"))) + CONTROL_SOURCE
)

# A ``@sighash`` directive on a non-TS surface. The Solidity parser drops
# comments, so honouring this source would silently sign with the default
# sighash type instead of the requested one.
DIRECTIVE_SOURCE = "// @sighash SINGLE|FORKID\n" + CONTROL_SOURCE


assert len(OVERSIZE_SOURCE.encode("utf-8")) == MAX_SOURCE_BYTES + 1


# ---------------------------------------------------------------------------
# Entry-point adapters
#
# Every adapter returns (rejected, detail). "Rejected" means the entry point
# refused to produce a compilation result -- by raising, by reporting error
# diagnostics, or (for the CLI) by exiting non-zero.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EntryPoint:
    name: str
    run: Callable[[str], tuple[bool, str]]


def _write_temp(source: str, tmp_dir: str) -> str:
    path = os.path.join(tmp_dir, SOURCE_NAME)
    with open(path, "w", encoding="utf-8") as f:
        f.write(source)
    return path


def _api_compile_from_source(source: str) -> tuple[bool, str]:
    with tempfile.TemporaryDirectory() as d:
        path = _write_temp(source, d)
        try:
            artifact = compile_from_source(path)
        except Exception as e:  # noqa: BLE001 -- any refusal counts
            return True, f"{type(e).__name__}: {e}"
        return False, f"compiled, script hex length {len(artifact.script)}"


def _api_compile_source_to_ir(source: str) -> tuple[bool, str]:
    with tempfile.TemporaryDirectory() as d:
        path = _write_temp(source, d)
        try:
            program = compile_source_to_ir(path)
        except Exception as e:  # noqa: BLE001
            return True, f"{type(e).__name__}: {e}"
        return False, f"lowered to ANF, {len(program.methods)} method(s)"


def _api_compile_from_source_with_result(source: str) -> tuple[bool, str]:
    with tempfile.TemporaryDirectory() as d:
        path = _write_temp(source, d)
        result = compile_from_source_with_result(path)
    if result.has_errors():
        return True, "; ".join(d.format_message() for d in result.diagnostics)
    return False, f"compiled, script hex length {len(result.script_hex or '')}"


def _api_compile_from_source_str_with_result(source: str) -> tuple[bool, str]:
    result = compile_from_source_str_with_result(source, SOURCE_NAME)
    if result.has_errors():
        return True, "; ".join(d.format_message() for d in result.diagnostics)
    return False, f"compiled, script hex length {len(result.script_hex or '')}"


def _cli(source: str, extra_args: Callable[[str], list[str]]) -> tuple[bool, str]:
    with tempfile.TemporaryDirectory() as d:
        path = _write_temp(source, d)
        proc = subprocess.run(
            [sys.executable, "-m", "runar_compiler", "--source", path, *extra_args(d)],
            cwd=str(PYTHON_COMPILER_DIR),
            capture_output=True,
            text=True,
            timeout=120,
            env=os.environ.copy(),
        )
    if proc.returncode != 0:
        # Tail, not head: a clean rejection is one line, and if the CLI ever
        # regresses to dumping a traceback the reason is at the END of it.
        return True, f"exit {proc.returncode}: {proc.stderr.strip()[-600:]}"
    return False, f"exit 0, {len(proc.stdout)} bytes on stdout"


ENTRY_POINTS = [
    EntryPoint("compile_from_source", _api_compile_from_source),
    EntryPoint("compile_source_to_ir", _api_compile_source_to_ir),
    EntryPoint(
        "compile_from_source_with_result", _api_compile_from_source_with_result
    ),
    EntryPoint(
        "compile_from_source_str_with_result",
        _api_compile_from_source_str_with_result,
    ),
    EntryPoint("cli:--source", lambda s: _cli(s, lambda d: [])),
    EntryPoint("cli:--hex", lambda s: _cli(s, lambda d: ["--hex"])),
    EntryPoint("cli:--asm", lambda s: _cli(s, lambda d: ["--asm"])),
    EntryPoint("cli:--emit-ir", lambda s: _cli(s, lambda d: ["--emit-ir"])),
    EntryPoint(
        "cli:--emit-ir-to",
        lambda s: _cli(s, lambda d: ["--emit-ir-to", os.path.join(d, "ir.json")]),
    ),
    EntryPoint("cli:--parse-only", lambda s: _cli(s, lambda d: ["--parse-only"])),
]

ENTRY_POINT_IDS = [e.name for e in ENTRY_POINTS]


# ---------------------------------------------------------------------------
# Control: an ordinary source must still compile everywhere.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("entry", ENTRY_POINTS, ids=ENTRY_POINT_IDS)
def test_control_source_compiles_through_every_entry_point(entry: EntryPoint) -> None:
    rejected, detail = entry.run(CONTROL_SOURCE)
    assert not rejected, f"{entry.name} rejected a legitimate source: {detail}"


# ---------------------------------------------------------------------------
# Guard 1: the 4 MiB DoS bound.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("entry", ENTRY_POINTS, ids=ENTRY_POINT_IDS)
def test_oversize_source_rejected_by_every_entry_point(entry: EntryPoint) -> None:
    rejected, detail = entry.run(OVERSIZE_SOURCE)
    assert rejected, (
        f"{entry.name} accepted a {len(OVERSIZE_SOURCE.encode('utf-8'))}-byte source "
        f"(limit {MAX_SOURCE_BYTES}): {detail}"
    )
    assert "MAX_SOURCE_BYTES" in detail, (
        f"{entry.name} rejected the oversize source for the wrong reason: {detail}"
    )
    assert "Traceback (most recent call last)" not in detail, (
        f"{entry.name} rejected the oversize source with an uncaught traceback "
        f"instead of a diagnostic: {detail}"
    )


# ---------------------------------------------------------------------------
# Guard 2: fail-closed @sighash / @embedAlways on non-TS surfaces.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("entry", ENTRY_POINTS, ids=ENTRY_POINT_IDS)
def test_non_ts_directive_rejected_by_every_entry_point(entry: EntryPoint) -> None:
    rejected, detail = entry.run(DIRECTIVE_SOURCE)
    assert rejected, (
        f"{entry.name} silently dropped an @sighash directive on the Solidity "
        f"surface: {detail}"
    )
    assert "@sighash" in detail, (
        f"{entry.name} rejected the directive source for the wrong reason: {detail}"
    )
    assert "Traceback (most recent call last)" not in detail, (
        f"{entry.name} rejected the directive source with an uncaught traceback "
        f"instead of a diagnostic: {detail}"
    )


# ---------------------------------------------------------------------------
# Structural: the guarded dispatcher must be the only dispatcher.
#
# The root cause of R-024 was a second, hand-maintained nine-way extension
# chain that no guard protected. Pin that there is exactly one.
# ---------------------------------------------------------------------------


def test_compiler_module_has_no_second_dispatcher() -> None:
    src = (PYTHON_COMPILER_DIR / "runar_compiler" / "compiler.py").read_text(
        encoding="utf-8"
    )
    for parser_fn in (
        "parse_python",
        "parse_ts",
        "parse_sol",
        "parse_move",
        "parse_go",
        "parse_rust",
        "parse_ruby",
        "parse_zig",
        "parse_java",
    ):
        assert parser_fn not in src, (
            f"compiler.py dispatches to {parser_fn} directly — a second "
            "extension-dispatch chain that bypasses parser_dispatch's guards"
        )


def test_production_code_routes_through_the_guarded_dispatcher() -> None:
    pkg = PYTHON_COMPILER_DIR / "runar_compiler"
    importers = set()
    for path in pkg.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if "parser_dispatch import parse_source" in text or (
            "parser_dispatch" in text and "parse_source(" in text
        ):
            importers.add(path.name)
    assert "compiler.py" in importers, (
        "compiler.py does not import the guarded parser_dispatch.parse_source; "
        f"guarded-dispatcher importers found: {sorted(importers)}"
    )

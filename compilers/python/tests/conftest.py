"""Shared test fixtures and helpers for the Python compiler test suite."""

from __future__ import annotations

import json
from pathlib import Path

from runar_compiler.compiler import compile_from_ir_bytes, compile_from_source, Artifact


CONFORMANCE_DIR = Path(__file__).resolve().parent.parent.parent.parent / "conformance" / "tests"


def conformance_dir() -> Path:
    """Return the path to the conformance test suite."""
    return CONFORMANCE_DIR


def load_conformance_ir(test_name: str) -> str:
    """Read the expected-ir.json for a given conformance test."""
    path = CONFORMANCE_DIR / test_name / "expected-ir.json"
    return path.read_text(encoding="utf-8")


def load_conformance_script(test_name: str) -> str:
    """Read the expected-script.hex for a given conformance test."""
    path = CONFORMANCE_DIR / test_name / "expected-script.hex"
    return path.read_text(encoding="utf-8").strip()


def must_compile_ir(json_str: str, disable_constant_folding: bool = False) -> Artifact:
    """Compile IR JSON to an Artifact, raising on failure."""
    return compile_from_ir_bytes(
        json_str.encode("utf-8"),
        disable_constant_folding=disable_constant_folding,
    )


def must_compile_source(path: str, disable_constant_folding: bool = False) -> Artifact:
    """Compile a source file to an Artifact, raising on failure."""
    return compile_from_source(path, disable_constant_folding=disable_constant_folding)


def iter_opcodes(script_hex: str) -> list[str]:
    """Walk ``script_hex`` opcode by opcode, skipping push-data payload bytes,
    and return the 2-hex-char opcode bytes actually executed as instructions,
    in script order.

    This exists so tests can assert "opcode X is present in this script"
    without a bare substring check (``"XX" in script_hex``), which also
    matches ``XX`` when it happens to land inside a push-data payload or
    straddles two adjacent bytes -- noise that grows with script length
    (CL-GAP-162 measured a 14%-79% false-pass rate against random hex,
    depending on length). Checking membership in this opcode list only ever
    matches a byte that the VM would actually execute as that opcode.

    Push instructions (direct pushes 0x01-0x4b, OP_PUSHDATA1/2/4) are
    themselves included as opcode bytes -- only their payload is skipped.
    """
    data = bytes.fromhex(script_hex)
    opcodes: list[str] = []
    i = 0
    n = len(data)
    while i < n:
        b = data[i]
        opcodes.append(f"{b:02x}")
        if 1 <= b <= 0x4B:
            i += 1 + b
        elif b == 0x4C:  # OP_PUSHDATA1: 1-byte length follows
            if i + 1 >= n:
                break
            i += 2 + data[i + 1]
        elif b == 0x4D:  # OP_PUSHDATA2: 2-byte little-endian length follows
            if i + 2 >= n:
                break
            i += 3 + int.from_bytes(data[i + 1:i + 3], "little")
        elif b == 0x4E:  # OP_PUSHDATA4: 4-byte little-endian length follows
            if i + 4 >= n:
                break
            i += 5 + int.from_bytes(data[i + 1:i + 5], "little")
        else:
            i += 1
    return opcodes

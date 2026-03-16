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

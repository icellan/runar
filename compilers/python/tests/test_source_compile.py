"""Source-to-script compilation tests and compiler parity checks.

Mirrors the TestSourceCompile_* and TestCompilerParity_* tests in Go.
Compiles conformance .runar.ts source files through the full pipeline and
verifies both opcode presence and golden-file hex match.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from conftest import conformance_dir, must_compile_source, load_conformance_script


def _source_path(test_name: str) -> str:
    """Get the .runar.ts source path for a conformance test."""
    source_dir = conformance_dir() / test_name
    for f in source_dir.iterdir():
        if f.name.endswith(".runar.ts"):
            return str(f)
    raise FileNotFoundError(f"No .runar.ts file in {source_dir}")


# ---------------------------------------------------------------------------
# Source compilation — opcode checks
# ---------------------------------------------------------------------------

class TestSourceCompile:
    def test_source_compile_p2pkh(self):
        artifact = must_compile_source(_source_path("basic-p2pkh"))
        assert "OP_HASH160" in artifact.asm
        assert "OP_CHECKSIG" in artifact.asm

    def test_source_compile_arithmetic(self):
        artifact = must_compile_source(_source_path("arithmetic"))
        assert "OP_ADD" in artifact.asm

    def test_source_compile_boolean_logic(self):
        artifact = must_compile_source(_source_path("boolean-logic"))
        assert "OP_BOOLAND" in artifact.asm

    def test_source_compile_if_else(self):
        artifact = must_compile_source(_source_path("if-else"))
        assert "OP_IF" in artifact.asm

    def test_source_compile_bounded_loop(self):
        artifact = must_compile_source(_source_path("bounded-loop"))
        assert len(artifact.script) > 0

    def test_source_compile_multi_method(self):
        artifact = must_compile_source(_source_path("multi-method"))
        assert "OP_IF" in artifact.asm

    def test_source_compile_stateful(self):
        artifact = must_compile_source(_source_path("stateful"))
        assert "OP_HASH256" in artifact.asm


# ---------------------------------------------------------------------------
# Compiler parity — golden file match
# ---------------------------------------------------------------------------

PARITY_TESTS = [
    "arithmetic",
    "basic-p2pkh",
    "boolean-logic",
    "bounded-loop",
    "if-else",
    "multi-method",
    "stateful",
]


class TestCompilerParity:
    @pytest.mark.parametrize("test_name", PARITY_TESTS)
    def test_compiler_parity_all(self, test_name: str):
        source_path = _source_path(test_name)
        expected_hex = load_conformance_script(test_name)

        # Disable constant folding to match golden files
        artifact = must_compile_source(source_path, disable_constant_folding=True)
        assert artifact.script == expected_hex, (
            f"Parity mismatch for {test_name}:\n"
            f"  expected: {expected_hex}\n"
            f"  got:      {artifact.script}"
        )


def _rb_source_path(test_name: str) -> str | None:
    """Get the .runar.rb source path for a conformance test, or None if absent."""
    source_dir = conformance_dir() / test_name
    for f in source_dir.iterdir():
        if f.name.endswith(".runar.rb"):
            return str(f)
    return None


class TestRubyCompilerParity:
    """Verify that .runar.rb files compile to the same hex as the golden file."""

    @pytest.mark.parametrize("test_name", PARITY_TESTS)
    def test_ruby_compiler_parity_all(self, test_name: str):
        rb_path = _rb_source_path(test_name)
        if rb_path is None:
            pytest.skip(f"No .runar.rb file for {test_name}")

        expected_hex = load_conformance_script(test_name)
        artifact = must_compile_source(rb_path)
        assert artifact.script == expected_hex, (
            f"Ruby parity mismatch for {test_name}:\n"
            f"  expected: {expected_hex}\n"
            f"  got:      {artifact.script}"
        )

"""Multi-format parsing tests.

Mirrors compilers/go/compiler_multiformat_test.go — verifies cross-format
consistency (all formats produce the same AST properties/methods) and
format-specific parsing correctness.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from runar_compiler.frontend.parser_dispatch import parse_source
from runar_compiler.frontend.validator import validate
from runar_compiler.frontend.typecheck import type_check
from runar_compiler.frontend.anf_lower import lower_to_anf

from conftest import conformance_dir


def _read_source(test_name: str, ext: str) -> str | None:
    """Read a conformance test source file, returning None if not found."""
    source_dir = conformance_dir() / test_name
    for f in source_dir.iterdir():
        if f.name.endswith(ext):
            return f.read_text(encoding="utf-8")
    return None


def _file_name(test_name: str, ext: str) -> str | None:
    """Get the file name for a conformance test source."""
    source_dir = conformance_dir() / test_name
    for f in source_dir.iterdir():
        if f.name.endswith(ext):
            return f.name
    return None


def _parse_and_lower(test_name: str, ext: str):
    """Parse + validate + typecheck + ANF lower a conformance test source."""
    source = _read_source(test_name, ext)
    assert source is not None, f"No {ext} file for {test_name}"
    fname = _file_name(test_name, ext)
    assert fname is not None

    result = parse_source(source, fname)
    assert len(result.errors) == 0, f"Parse errors for {test_name}{ext}: {result.errors}"
    assert result.contract is not None

    valid_result = validate(result.contract)
    assert len(valid_result.errors) == 0, f"Validation errors: {valid_result.errors}"

    tc_result = type_check(result.contract)
    assert len(tc_result.errors) == 0, f"Typecheck errors: {tc_result.errors}"

    return lower_to_anf(result.contract)


# Tests that have all 6 source formats
MULTI_FORMAT_TESTS = [
    "arithmetic",
    "basic-p2pkh",
    "boolean-logic",
    "bounded-loop",
    "if-else",
]

# Stateful has mutable properties whose readonly flag may vary by format parser
# (e.g. Move resource struct marks all fields readonly). Test separately.
MULTI_FORMAT_TESTS_WITH_STATEFUL = MULTI_FORMAT_TESTS + ["stateful"]

FORMATS = [".runar.ts", ".runar.sol", ".runar.move", ".runar.go", ".runar.rs", ".runar.py", ".runar.rb"]


# ---------------------------------------------------------------------------
# Cross-format consistency
# ---------------------------------------------------------------------------

class TestCrossFormatConsistency:
    @pytest.mark.parametrize("test_name", MULTI_FORMAT_TESTS)
    def test_cross_format_property_consistency(self, test_name: str):
        """All formats produce the same property names, types, and readonly flags."""
        programs = {}
        for ext in FORMATS:
            source = _read_source(test_name, ext)
            if source is None:
                continue
            fname = _file_name(test_name, ext)
            programs[ext] = _parse_and_lower(test_name, ext)

        assert len(programs) >= 2, f"Need at least 2 formats for {test_name}"

        reference_ext = ".runar.ts"
        reference = programs[reference_ext]
        ref_props = [(p.name, p.type, p.readonly) for p in reference.properties]

        for ext, prog in programs.items():
            if ext == reference_ext:
                continue
            other_props = [(p.name, p.type, p.readonly) for p in prog.properties]
            assert ref_props == other_props, (
                f"Property mismatch between {reference_ext} and {ext} for {test_name}:\n"
                f"  {reference_ext}: {ref_props}\n"
                f"  {ext}: {other_props}"
            )

    @pytest.mark.parametrize("test_name", MULTI_FORMAT_TESTS_WITH_STATEFUL)
    def test_cross_format_method_param_consistency(self, test_name: str):
        """All formats produce the same method names, params, and visibility."""
        programs = {}
        for ext in FORMATS:
            source = _read_source(test_name, ext)
            if source is None:
                continue
            programs[ext] = _parse_and_lower(test_name, ext)

        assert len(programs) >= 2

        reference_ext = ".runar.ts"
        reference = programs[reference_ext]

        def method_sig(prog):
            return [
                (m.name, [(p.name, p.type) for p in m.params], m.is_public)
                for m in prog.methods
            ]

        ref_sigs = method_sig(reference)

        for ext, prog in programs.items():
            if ext == reference_ext:
                continue
            other_sigs = method_sig(prog)
            assert ref_sigs == other_sigs, (
                f"Method signature mismatch between {reference_ext} and {ext} for {test_name}:\n"
                f"  {reference_ext}: {ref_sigs}\n"
                f"  {ext}: {other_sigs}"
            )


# ---------------------------------------------------------------------------
# Format-specific parsing
# ---------------------------------------------------------------------------

class TestFormatSpecificParsing:
    def test_parse_sol_arithmetic_structure(self):
        program = _parse_and_lower("arithmetic", ".runar.sol")

        assert program.contract_name == "Arithmetic"
        assert len(program.properties) == 1
        assert program.properties[0].name == "target"
        assert program.properties[0].type == "bigint"

        verify = [m for m in program.methods if m.name == "verify"][0]
        assert verify.is_public is True
        assert len(verify.params) == 2

    def test_parse_move_arithmetic_structure(self):
        program = _parse_and_lower("arithmetic", ".runar.move")

        assert program.contract_name == "Arithmetic"
        assert len(program.properties) == 1
        assert program.properties[0].name == "target"

        verify = [m for m in program.methods if m.name == "verify"][0]
        assert verify.is_public is True

    def test_parse_python_p2pkh(self):
        program = _parse_and_lower("basic-p2pkh", ".runar.py")

        assert program.contract_name == "P2PKH"
        assert len(program.properties) == 1
        assert program.properties[0].name == "pubKeyHash"
        assert program.properties[0].type == "Addr"

        unlock = [m for m in program.methods if m.name == "unlock"][0]
        assert unlock.is_public is True
        assert len(unlock.params) == 2
        assert unlock.params[0].name == "sig"
        assert unlock.params[1].name == "pubKey"

    def test_parse_go_p2pkh(self):
        program = _parse_and_lower("basic-p2pkh", ".runar.go")

        assert program.contract_name == "P2PKH"
        assert len(program.properties) == 1
        assert program.properties[0].name == "pubKeyHash"

    def test_parse_rust_p2pkh(self):
        program = _parse_and_lower("basic-p2pkh", ".runar.rs")

        assert program.contract_name == "P2PKH"
        assert len(program.properties) == 1
        assert program.properties[0].name == "pubKeyHash"

    def test_parse_python_boolean_logic(self):
        program = _parse_and_lower("boolean-logic", ".runar.py")

        assert program.contract_name == "BooleanLogic"
        verify = [m for m in program.methods if m.name == "verify"][0]
        assert len(verify.params) == 3

    def test_parse_sol_stateful(self):
        program = _parse_and_lower("stateful", ".runar.sol")

        assert program.contract_name == "Stateful"
        # Stateful contracts have mutable properties
        has_mutable = any(not p.readonly for p in program.properties)
        assert has_mutable, "Stateful contract should have mutable properties"

    def test_parse_ruby_p2pkh(self):
        program = _parse_and_lower("basic-p2pkh", ".runar.rb")

        assert program.contract_name == "P2PKH"
        assert len(program.properties) == 1
        assert program.properties[0].name == "pubKeyHash"
        assert program.properties[0].type == "Addr"
        assert program.properties[0].readonly is True

        unlock = [m for m in program.methods if m.name == "unlock"][0]
        assert unlock.is_public is True
        assert len(unlock.params) == 2
        assert unlock.params[0].name == "sig"
        assert unlock.params[1].name == "pubKey"

    def test_parse_ruby_stateful(self):
        program = _parse_and_lower("stateful", ".runar.rb")

        assert program.contract_name == "Stateful"
        # count is mutable, maxCount is readonly
        count_prop = next(p for p in program.properties if p.name == "count")
        max_count_prop = next(p for p in program.properties if p.name == "maxCount")
        assert count_prop.readonly is False
        assert max_count_prop.readonly is True

    def test_parse_ruby_arithmetic(self):
        program = _parse_and_lower("arithmetic", ".runar.rb")

        assert program.contract_name == "Arithmetic"
        verify = [m for m in program.methods if m.name == "verify"][0]
        assert verify.is_public is True
        assert len(verify.params) == 2

        bin_ops = [b.value.op for b in verify.body if b.value.kind == "bin_op"]
        assert "+" in bin_ops
        assert "-" in bin_ops
        assert "*" in bin_ops
        assert "/" in bin_ops

    def test_parse_ruby_boolean_logic(self):
        program = _parse_and_lower("boolean-logic", ".runar.rb")

        assert program.contract_name == "BooleanLogic"
        verify = [m for m in program.methods if m.name == "verify"][0]
        assert verify.is_public is True
        assert len(verify.params) == 3

        bin_ops = [b.value.op for b in verify.body if b.value.kind == "bin_op"]
        assert "&&" in bin_ops
        assert "||" in bin_ops

    def test_parse_ruby_if_else(self):
        program = _parse_and_lower("if-else", ".runar.rb")

        assert program.contract_name == "IfElse"
        check = [m for m in program.methods if m.name == "check"][0]
        kinds = [b.value.kind for b in check.body]
        assert "if" in kinds

    def test_parse_ruby_bounded_loop(self):
        program = _parse_and_lower("bounded-loop", ".runar.rb")

        assert program.contract_name == "BoundedLoop"
        verify = [m for m in program.methods if m.name == "verify"][0]
        # ANF lowering converts for loops to a ``loop`` binding
        kinds = [b.value.kind for b in verify.body]
        assert "loop" in kinds

    def test_parse_ruby_multi_method(self):
        program = _parse_and_lower("multi-method", ".runar.rb")

        assert program.contract_name == "MultiMethod"
        # computeThreshold should be a private method
        compute = next(m for m in program.methods if m.name == "computeThreshold")
        assert compute.is_public is False
        # spendWithOwner should be public and contain a call to computeThreshold
        # (bare method call rewritten to this.computeThreshold)
        spend_owner = next(m for m in program.methods if m.name == "spendWithOwner")
        assert spend_owner.is_public is True

    def test_parse_ruby_ec_primitives(self):
        program = _parse_and_lower("ec-primitives", ".runar.rb")

        assert program.contract_name == "ECPrimitives"
        assert len(program.properties) == 1
        assert program.properties[0].name == "pt"
        assert program.properties[0].type == "Point"

    def test_parse_ruby_post_quantum_wots(self):
        program = _parse_and_lower("post-quantum-wots", ".runar.rb")

        assert program.contract_name == "PostQuantumWOTS"
        spend = [m for m in program.methods if m.name == "spend"][0]
        # verifyWOTS should appear in the ANF bindings (``call`` nodes have a ``func`` field)
        funcs = [b.value.func for b in spend.body if b.value.kind == "call"]
        assert "verifyWOTS" in funcs

    def test_parse_ruby_post_quantum_slhdsa(self):
        program = _parse_and_lower("post-quantum-slhdsa", ".runar.rb")

        assert program.contract_name == "PostQuantumSLHDSA"
        spend = [m for m in program.methods if m.name == "spend"][0]
        funcs = [b.value.func for b in spend.body if b.value.kind == "call"]
        assert "verifySLHDSA_SHA2_128s" in funcs

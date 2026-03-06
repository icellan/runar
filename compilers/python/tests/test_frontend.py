"""Frontend tests: parser dispatch, validator, type checker, and ANF lowering.

Mirrors compilers/go/frontend/*_test.go — verifies that each frontend pass
works correctly on standard Rúnar contracts.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from runar_compiler.frontend.parser_dispatch import parse_source
from runar_compiler.frontend.validator import validate
from runar_compiler.frontend.typecheck import type_check
from runar_compiler.frontend.anf_lower import lower_to_anf

from conftest import conformance_dir


def _read_source(test_name: str, ext: str) -> str:
    """Read a conformance test source file."""
    source_dir = conformance_dir() / test_name
    # Source files are named like: basic-p2pkh.runar.ts
    for f in source_dir.iterdir():
        if f.name.endswith(ext):
            return f.read_text(encoding="utf-8")
    raise FileNotFoundError(f"No {ext} file in {source_dir}")


def _source_path(test_name: str, ext: str) -> str:
    """Get path to a conformance test source file."""
    source_dir = conformance_dir() / test_name
    for f in source_dir.iterdir():
        if f.name.endswith(ext):
            return str(f)
    raise FileNotFoundError(f"No {ext} file in {source_dir}")


def _file_name(test_name: str, ext: str) -> str:
    """Get the file name for a conformance test source."""
    source_dir = conformance_dir() / test_name
    for f in source_dir.iterdir():
        if f.name.endswith(ext):
            return f.name
    raise FileNotFoundError(f"No {ext} file in {source_dir}")


# ---------------------------------------------------------------------------
# Parser dispatch
# ---------------------------------------------------------------------------

class TestParserDispatch:
    def test_parse_dispatch_ts(self):
        source = _read_source("basic-p2pkh", ".runar.ts")
        result = parse_source(source, "P2PKH.runar.ts")

        assert len(result.errors) == 0
        assert result.contract is not None
        assert result.contract.name == "P2PKH"

    def test_parse_dispatch_sol(self):
        source = _read_source("basic-p2pkh", ".runar.sol")
        result = parse_source(source, "P2PKH.runar.sol")

        assert len(result.errors) == 0
        assert result.contract is not None
        assert result.contract.name == "P2PKH"

    def test_parse_dispatch_move(self):
        source = _read_source("basic-p2pkh", ".runar.move")
        result = parse_source(source, "P2PKH.runar.move")

        assert len(result.errors) == 0
        assert result.contract is not None
        assert result.contract.name == "P2PKH"

    def test_parse_dispatch_py(self):
        source = _read_source("basic-p2pkh", ".runar.py")
        result = parse_source(source, "P2PKH.runar.py")

        assert len(result.errors) == 0
        assert result.contract is not None
        assert result.contract.name == "P2PKH"

    def test_parse_dispatch_go(self):
        source = _read_source("basic-p2pkh", ".runar.go")
        result = parse_source(source, "P2PKH.runar.go")

        assert len(result.errors) == 0
        assert result.contract is not None
        assert result.contract.name == "P2PKH"

    def test_parse_dispatch_rs(self):
        source = _read_source("basic-p2pkh", ".runar.rs")
        result = parse_source(source, "P2PKH.runar.rs")

        assert len(result.errors) == 0
        assert result.contract is not None
        assert result.contract.name == "P2PKH"

    def test_parse_dispatch_unknown(self):
        result = parse_source("anything", "test.runar.xyz")
        assert len(result.errors) > 0


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------

class TestValidator:
    def test_validate_valid_p2pkh(self):
        source = _read_source("basic-p2pkh", ".runar.ts")
        result = parse_source(source, "P2PKH.runar.ts")
        assert result.contract is not None

        valid_result = validate(result.contract)
        assert len(valid_result.errors) == 0

    def test_validate_constructor_missing_super(self):
        source = """
import { SmartContract, assert } from 'runar-lang';

class Bad extends SmartContract {
  readonly x: bigint;

  constructor(x: bigint) {
    this.x = x;
  }

  public check(): void {
    assert(this.x > 0n);
  }
}
"""
        result = parse_source(source, "Bad.runar.ts")
        assert result.contract is not None

        valid_result = validate(result.contract)
        assert any("super" in e.lower() for e in valid_result.errors)

    def test_validate_stateful_no_trailing_assert(self):
        """Stateful contract methods don't need a trailing assert."""
        source = _read_source("stateful", ".runar.ts")
        result = parse_source(source, "Stateful.runar.ts")
        assert result.contract is not None

        valid_result = validate(result.contract)
        assert len(valid_result.errors) == 0


# ---------------------------------------------------------------------------
# Type checker
# ---------------------------------------------------------------------------

class TestTypeChecker:
    def test_typecheck_valid_p2pkh(self):
        source = _read_source("basic-p2pkh", ".runar.ts")
        result = parse_source(source, "P2PKH.runar.ts")
        assert result.contract is not None
        validate(result.contract)

        tc_result = type_check(result.contract)
        assert len(tc_result.errors) == 0

    def test_typecheck_unknown_function(self):
        source = """
import { SmartContract, assert } from 'runar-lang';

class Bad extends SmartContract {
  readonly x: bigint;

  constructor(x: bigint) {
    super(x);
    this.x = x;
  }

  public check(): void {
    const y = Math.floor(3.14);
    assert(this.x > 0n);
  }
}
"""
        result = parse_source(source, "Bad.runar.ts")
        assert result.contract is not None
        validate(result.contract)

        tc_result = type_check(result.contract)
        assert len(tc_result.errors) > 0

    def test_typecheck_valid_arithmetic(self):
        source = _read_source("arithmetic", ".runar.ts")
        result = parse_source(source, "Arithmetic.runar.ts")
        assert result.contract is not None
        validate(result.contract)

        tc_result = type_check(result.contract)
        assert len(tc_result.errors) == 0


# ---------------------------------------------------------------------------
# ANF lowering
# ---------------------------------------------------------------------------

class TestANFLowering:
    def _get_p2pkh_program(self):
        source = _read_source("basic-p2pkh", ".runar.ts")
        result = parse_source(source, "P2PKH.runar.ts")
        assert result.contract is not None
        validate(result.contract)
        type_check(result.contract)
        return lower_to_anf(result.contract)

    def test_anf_lower_p2pkh_properties(self):
        program = self._get_p2pkh_program()

        assert program.contract_name == "P2PKH"
        assert len(program.properties) == 1
        assert program.properties[0].name == "pubKeyHash"
        assert program.properties[0].type == "Addr"
        assert program.properties[0].readonly is True

    def test_anf_lower_p2pkh_bindings(self):
        program = self._get_p2pkh_program()

        # Find the unlock method
        unlock = [m for m in program.methods if m.name == "unlock"][0]
        assert unlock.is_public is True
        assert len(unlock.params) == 2
        assert unlock.params[0].name == "sig"
        assert unlock.params[1].name == "pubKey"

        # Check binding kinds
        kinds = [b.value.kind for b in unlock.body]
        assert "load_param" in kinds
        assert "call" in kinds
        assert "load_prop" in kinds
        assert "bin_op" in kinds
        assert "assert" in kinds

    def test_anf_lower_arithmetic(self):
        source = _read_source("arithmetic", ".runar.ts")
        result = parse_source(source, "Arithmetic.runar.ts")
        assert result.contract is not None
        validate(result.contract)
        type_check(result.contract)

        program = lower_to_anf(result.contract)
        assert program.contract_name == "Arithmetic"

        # verify method should have binary ops for +, -, *, /
        verify = [m for m in program.methods if m.name == "verify"][0]
        bin_ops = [b.value.op for b in verify.body if b.value.kind == "bin_op"]
        assert "+" in bin_ops
        assert "-" in bin_ops
        assert "*" in bin_ops
        assert "/" in bin_ops

    def test_anf_lower_if_else(self):
        source = _read_source("if-else", ".runar.ts")
        result = parse_source(source, "IfElse.runar.ts")
        assert result.contract is not None
        validate(result.contract)
        type_check(result.contract)

        program = lower_to_anf(result.contract)
        check = [m for m in program.methods if m.name == "check"][0]
        kinds = [b.value.kind for b in check.body]
        assert "if" in kinds

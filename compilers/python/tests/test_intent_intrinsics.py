"""Tests for BSVM Phase 13 intent sub-covenant intrinsics in the Python tier.

Mirrors ``compilers/go/frontend/intent_intrinsics_test.go`` and
``compilers/go/compiler/intent_intrinsics_compile_test.go``. All three
intrinsics (``extractPrevOutputScript``, ``requireOutputP2PKH``,
``currentBlockHeight``) are pure frontend sugar — they desugar to
existing ANF primitives + auto-injected method params. See
``docs/cross-covenant-pattern.md``.
"""

from __future__ import annotations

import pytest

from runar_compiler.compiler import compile_from_source_str_with_result
from runar_compiler.frontend.anf_lower import lower_to_anf
from runar_compiler.frontend.diagnostic import Severity
from runar_compiler.frontend.parser_dispatch import parse_source
from runar_compiler.frontend.typecheck import type_check
from runar_compiler.frontend.validator import validate
from runar_compiler.ir.types import ANFProgram


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _must_lower_go_source(source: str) -> ANFProgram:
    """Parse, validate, typecheck, and ANF-lower a Go-DSL source string.
    Asserts every pass is clean."""
    result = parse_source(source, "Test.runar.go")
    assert result.errors == [], result.error_strings()
    assert result.contract is not None
    val_result = validate(result.contract)
    assert val_result.errors == [], [d.format_message() for d in val_result.errors]
    tc_result = type_check(result.contract)
    assert tc_result.errors == [], [d.format_message() for d in tc_result.errors]
    return lower_to_anf(result.contract)


def _expect_typecheck_error(source: str, substr: str) -> None:
    """Assert that the source produces a typecheck error containing ``substr``."""
    result = parse_source(source, "Test.runar.go")
    assert result.errors == [], result.error_strings()
    tc_result = type_check(result.contract)
    msgs = [d.format_message() for d in tc_result.errors]
    assert any(substr in m for m in msgs), (
        f"expected typecheck error containing {substr!r}, got: {msgs}"
    )


def _find_method(program: ANFProgram, name: str):
    for m in program.methods:
        if m.name == name:
            return m
    method_names = [m.name for m in program.methods]
    pytest.fail(f"method {name!r} not found; got: {method_names}")


def _param_names(method) -> list[str]:
    return [p.name for p in method.params]


# ---------------------------------------------------------------------------
# extractPrevOutputScript
# ---------------------------------------------------------------------------

class TestExtractPrevOutputScript:
    def test_auto_injects_witness_param(self):
        source = """
package x

import runar "github.com/icellan/runar/packages/runar-go"

type IntentCov struct {
    runar.StatefulSmartContract
    StateCovScriptHash runar.ByteString `runar:"readonly"`
}

func (c *IntentCov) CoSpend() {
    stateCovScript := runar.ExtractPrevOutputScript(0, c.StateCovScriptHash)
    _ = stateCovScript
}
"""
        program = _must_lower_go_source(source)
        m = _find_method(program, "coSpend")
        names = _param_names(m)
        assert "_prevOutScript_0" in names, names
        assert "txPreimage" in names, names

    def test_two_indices_produce_two_params(self):
        source = """
package x

import runar "github.com/icellan/runar/packages/runar-go"

type IntentCov struct {
    runar.StatefulSmartContract
    H0 runar.ByteString `runar:"readonly"`
    H1 runar.ByteString `runar:"readonly"`
}

func (c *IntentCov) CoSpend() {
    a := runar.ExtractPrevOutputScript(0, c.H0)
    b := runar.ExtractPrevOutputScript(1, c.H1)
    _ = a
    _ = b
}
"""
        program = _must_lower_go_source(source)
        m = _find_method(program, "coSpend")
        names = _param_names(m)
        assert "_prevOutScript_0" in names, names
        assert "_prevOutScript_1" in names, names

    def test_same_index_is_idempotent(self):
        source = """
package x

import runar "github.com/icellan/runar/packages/runar-go"

type IntentCov struct {
    runar.StatefulSmartContract
    H0 runar.ByteString `runar:"readonly"`
}

func (c *IntentCov) CoSpend() {
    a := runar.ExtractPrevOutputScript(0, c.H0)
    b := runar.ExtractPrevOutputScript(0, c.H0)
    _ = a
    _ = b
}
"""
        program = _must_lower_go_source(source)
        m = _find_method(program, "coSpend")
        count = sum(1 for p in m.params if p.name == "_prevOutScript_0")
        assert count == 1, f"expected exactly one _prevOutScript_0 param, got {count}"

    def test_non_literal_index_errors(self):
        source = """
package x

import runar "github.com/icellan/runar/packages/runar-go"

type IntentCov struct {
    runar.StatefulSmartContract
    H0 runar.ByteString `runar:"readonly"`
}

func (c *IntentCov) CoSpend(idx runar.Bigint) {
    _ = runar.ExtractPrevOutputScript(idx, c.H0)
}
"""
        _expect_typecheck_error(source, "must be an integer literal")

    # Crit-2 — 3-arg prefix-hash form ------------------------------------

    def test_prefix_form_lowers_with_substr(self):
        source = """
package x

import runar "github.com/icellan/runar/packages/runar-go"

type IntentTemplate struct {
    runar.StatefulSmartContract
    ExpectedPolicyPrefixHash runar.ByteString `runar:"readonly"`
}

func (c *IntentTemplate) Bind() {
    s := runar.ExtractPrevOutputScript(0, c.ExpectedPolicyPrefixHash, 600)
    _ = s
}
"""
        program = _must_lower_go_source(source)
        m = _find_method(program, "bind")

        # Build a name -> binding index map for back-references.
        binding_by_name = {b.name: i for i, b in enumerate(m.body)}

        saw_prefix_substr = False
        for i, b in enumerate(m.body):
            if (
                b.value.kind == "call"
                and b.value.func == "substr"
                and len(b.value.args) == 3
            ):
                first_arg_ref = b.value.args[0]
                j = binding_by_name.get(first_arg_ref)
                if j is not None and j < i:
                    inner = m.body[j].value
                    if inner.kind == "load_param" and inner.name == "_prevOutScript_0":
                        saw_prefix_substr = True
                        break
        assert saw_prefix_substr, (
            "expected substr(load_param(_prevOutScript_0), ...) for 3-arg prefix form"
        )

    def test_prefix_form_non_literal_prefix_len_errors(self):
        source = """
package x

import runar "github.com/icellan/runar/packages/runar-go"

type Cov struct {
    runar.StatefulSmartContract
    H runar.ByteString `runar:"readonly"`
}

func (c *Cov) Bind(n runar.Bigint) {
    _ = runar.ExtractPrevOutputScript(0, c.H, n)
}
"""
        _expect_typecheck_error(source, "prefixLen) must be an integer literal")

    def test_too_many_args_errors(self):
        source = """
package x

import runar "github.com/icellan/runar/packages/runar-go"

type Cov struct {
    runar.StatefulSmartContract
    H runar.ByteString `runar:"readonly"`
}

func (c *Cov) Bind() {
    _ = runar.ExtractPrevOutputScript(0, c.H, 600, 999)
}
"""
        _expect_typecheck_error(source, "expects 2 or 3 arguments")


# ---------------------------------------------------------------------------
# Crit-3 — requireOutputP2PKH + addDataOutput mix rejection
# ---------------------------------------------------------------------------

class TestRequireOutputP2PKHMixRejection:
    def test_mixed_with_add_data_output_errors(self):
        source = """
package x

import runar "github.com/icellan/runar/packages/runar-go"

type Cov struct {
    runar.StatefulSmartContract
    BondPKH runar.ByteString `runar:"readonly"`
    Bond    runar.Bigint     `runar:"readonly"`
    Tag     runar.ByteString `runar:"readonly"`
}

func (c *Cov) PayBondAndAnnounce() {
    c.AddDataOutput(0, c.Tag)
    runar.RequireOutputP2PKH(0, c.BondPKH, c.Bond)
}
"""
        _expect_typecheck_error(
            source, "mixes requireOutputP2PKH() with addDataOutput()"
        )

    def test_without_add_data_output_ok(self):
        source = """
package x

import runar "github.com/icellan/runar/packages/runar-go"

type Cov struct {
    runar.StatefulSmartContract
    BondPKH runar.ByteString `runar:"readonly"`
    Bond    runar.Bigint     `runar:"readonly"`
}

func (c *Cov) PayBond() {
    runar.RequireOutputP2PKH(0, c.BondPKH, c.Bond)
}
"""
        # Must lower cleanly (no errors).
        _must_lower_go_source(source)


# ---------------------------------------------------------------------------
# requireOutputP2PKH
# ---------------------------------------------------------------------------

class TestRequireOutputP2PKH:
    def test_auto_injects_serialised_outputs(self):
        source = """
package x

import runar "github.com/icellan/runar/packages/runar-go"

type Cov struct {
    runar.StatefulSmartContract
    BondPKH runar.ByteString `runar:"readonly"`
    Bond    runar.Bigint     `runar:"readonly"`
}

func (c *Cov) PayBond() {
    runar.RequireOutputP2PKH(0, c.BondPKH, c.Bond)
}
"""
        program = _must_lower_go_source(source)
        m = _find_method(program, "payBond")
        names = _param_names(m)
        assert "_serialisedOutputs" in names, names

    def test_multiple_calls_one_serialised_outputs_param(self):
        source = """
package x

import runar "github.com/icellan/runar/packages/runar-go"

type Cov struct {
    runar.StatefulSmartContract
    BondPKH runar.ByteString `runar:"readonly"`
    Bond    runar.Bigint     `runar:"readonly"`
}

func (c *Cov) PayMulti() {
    runar.RequireOutputP2PKH(0, c.BondPKH, c.Bond)
    runar.RequireOutputP2PKH(1, c.BondPKH, c.Bond)
}
"""
        program = _must_lower_go_source(source)
        m = _find_method(program, "payMulti")
        count = sum(1 for p in m.params if p.name == "_serialisedOutputs")
        assert count == 1, (
            f"expected exactly one _serialisedOutputs param across multiple "
            f"intrinsic calls, got {count}"
        )

    def test_non_literal_index_errors(self):
        source = """
package x

import runar "github.com/icellan/runar/packages/runar-go"

type Cov struct {
    runar.StatefulSmartContract
    BondPKH runar.ByteString `runar:"readonly"`
    Bond    runar.Bigint     `runar:"readonly"`
}

func (c *Cov) PayBond(idx runar.Bigint) {
    runar.RequireOutputP2PKH(idx, c.BondPKH, c.Bond)
}
"""
        _expect_typecheck_error(source, "must be an integer literal")


# ---------------------------------------------------------------------------
# currentBlockHeight
# ---------------------------------------------------------------------------

class TestCurrentBlockHeight:
    def test_desugars_to_extract_locktime(self):
        source = """
package x

import runar "github.com/icellan/runar/packages/runar-go"

type Cov struct {
    runar.StatefulSmartContract
    Deadline runar.Bigint `runar:"readonly"`
}

func (c *Cov) Spend() {
    h := runar.CurrentBlockHeight()
    runar.Assert(h <= c.Deadline)
}
"""
        program = _must_lower_go_source(source)
        m = _find_method(program, "spend")
        saw_extract_locktime = any(
            b.value.kind == "call" and b.value.func == "extractLocktime"
            for b in m.body
        )
        assert saw_extract_locktime, (
            "expected currentBlockHeight() to desugar to extractLocktime call "
            f"in {m.name}.body"
        )

    def test_stateless_contract_errors(self):
        source = """
package x

import runar "github.com/icellan/runar/packages/runar-go"

type Sl struct {
    runar.SmartContract
    Deadline runar.Bigint `runar:"readonly"`
}

func (c *Sl) Spend() bool {
    h := runar.CurrentBlockHeight()
    return h > c.Deadline
}
"""
        _expect_typecheck_error(source, "StatefulSmartContract")


# ---------------------------------------------------------------------------
# End-to-end compile
# ---------------------------------------------------------------------------

class TestIntentIntrinsicsEndToEndCompile:
    def test_all_three_intrinsics_compile_cleanly(self):
        """A contract exercising all three intent-covenant intrinsics
        compiles cleanly from Go source to Bitcoin Script hex. The
        compiled artifact must include the auto-injected witness
        parameters in its ABI."""
        source = """
package x

import runar "github.com/icellan/runar/packages/runar-go"

type IntentDemo struct {
    runar.StatefulSmartContract
    StateCovScriptHash runar.ByteString `runar:"readonly"`
    BondPKH            runar.ByteString `runar:"readonly"`
    BondAmount         runar.Bigint     `runar:"readonly"`
    Deadline           runar.Bigint     `runar:"readonly"`
}

func (c *IntentDemo) CoSpendPrivileged() {
    stateCovScript := runar.ExtractPrevOutputScript(0, c.StateCovScriptHash)
    _ = stateCovScript

    h := runar.CurrentBlockHeight()
    runar.Assert(h <= c.Deadline)

    runar.RequireOutputP2PKH(0, c.BondPKH, c.BondAmount)
}
"""
        result = compile_from_source_str_with_result(source, "IntentDemo.runar.go")
        if not result.success:
            msgs = [d.format_message() for d in result.diagnostics]
            pytest.fail(f"compile failed: {msgs}")
        assert result.artifact is not None
        assert result.script_hex, "expected non-empty Script hex in artifact"

        # Locate the public method's ABI entry.
        target = None
        for m in result.artifact.abi.methods:
            if m.name == "coSpendPrivileged":
                target = m
                break
        method_names = [m.name for m in result.artifact.abi.methods]
        assert target is not None, (
            f"method coSpendPrivileged not found in artifact ABI; got: {method_names}"
        )

        param_names = {p.name for p in target.params}
        for want in ("_prevOutScript_0", "_serialisedOutputs", "txPreimage"):
            assert want in param_names, (
                f"expected param {want!r} in coSpendPrivileged ABI; "
                f"got: {sorted(param_names)}"
            )

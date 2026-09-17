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
# requireOutputP2PKH(0) vs the implicit single-output state continuation
# ---------------------------------------------------------------------------

class TestRequireOutputP2PKHSingleOutputContinuation:
    """A StatefulSmartContract method that mutates state but adds no explicit
    ``this.addOutput()``/``addRawOutput()`` takes the single-output state
    continuation path: the compiler re-creates the contract's own (large
    codePart) script at output index 0. ``requireOutputP2PKH(0, ...)`` also
    asserts output 0 is a 34-byte P2PKH — impossible for any codePart >= 253
    bytes — so the contract is permanently unspendable. The terminal case (no
    state mutation, no continuation) stays valid. Mirrors the TS reference
    describe 'requireOutputP2PKH(0) + single-output state continuation'.
    """

    # payBond mutates count (single-output continuation at output 0) AND
    # asserts output 0 is a bond P2PKH — output 0 cannot be both the codePart
    # and a P2PKH.
    _MUTATING = """
from runar import (
    StatefulSmartContract, ByteString, Bigint, Readonly, public,
)


class Bond(StatefulSmartContract):
    bondPKH: Readonly[ByteString]
    bond: Readonly[Bigint]
    count: Bigint

    def __init__(self, bondPKH: ByteString, bond: Bigint, count: Bigint):
        super().__init__(bondPKH, bond, count)
        self.bondPKH = bondPKH
        self.bond = bond
        self.count = count

    @public
    def payBond(self):
        requireOutputP2PKH(0, self.bondPKH, self.bond)
        self.count = self.count + 1
"""

    # Terminal: no state mutation -> no continuation -> output 0 is free to be
    # the required P2PKH.
    _TERMINAL = """
from runar import (
    StatefulSmartContract, ByteString, Bigint, Readonly, public,
)


class Bond(StatefulSmartContract):
    bondPKH: Readonly[ByteString]
    bond: Readonly[Bigint]
    count: Bigint

    def __init__(self, bondPKH: ByteString, bond: Bigint, count: Bigint):
        super().__init__(bondPKH, bond, count)
        self.bondPKH = bondPKH
        self.bond = bond
        self.count = count

    @public
    def payBond(self):
        requireOutputP2PKH(0, self.bondPKH, self.bond)
"""

    def test_mutating_variant_permanently_unspendable(self):
        result = parse_source(self._MUTATING, "Bond.runar.py")
        assert result.errors == [], result.error_strings()
        tc_result = type_check(result.contract)
        msgs = [d.format_message() for d in tc_result.errors]
        assert any("permanently unspendable" in m for m in msgs), (
            f"expected 'permanently unspendable' typecheck error, got: {msgs}"
        )

    def test_terminal_variant_accepted(self):
        result = parse_source(self._TERMINAL, "Bond.runar.py")
        assert result.errors == [], result.error_strings()
        tc_result = type_check(result.contract)
        msgs = [d.format_message() for d in tc_result.errors]
        assert tc_result.errors == [], (
            f"expected clean typecheck for terminal method, got: {msgs}"
        )


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
    // W2: both calls name index 0 -- any literal index above 0 is refused now.
    runar.RequireOutputP2PKH(0, c.BondPKH, c.Bond)
    runar.RequireOutputP2PKH(0, c.BondPKH, c.Bond)
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


# ---------------------------------------------------------------------------
# requireOutputP2PKH — the serialised-output hash binding must be emitted on
# EVERY control-flow path that asserts an output, not just the first one
# lowered (R-023 / CX-BUG-053).
#
# The intrinsic's per-output assertion compares a substring of the
# auto-injected witness ``_serialisedOutputs`` against the expected P2PKH
# bytes. That witness is attacker-supplied; the ONLY thing tying it to the
# transaction actually being signed is
#   assert(hash256(_serialisedOutputs) === extractOutputHash(txPreimage))
# If a branch omits that binding, a spender taking that branch can pass any
# bytes they like as ``_serialisedOutputs`` and the covenant enforces nothing
# about the real outputs.
# ---------------------------------------------------------------------------

def _binding_kinds(bindings):
    return [(b.name, b.value.kind, getattr(b.value, "func", None)) for b in bindings]


def _has_output_hash_binding(bindings) -> bool:
    """True iff ``bindings`` (one straight-line list, no recursion into
    nested ifs) contains the hash256(_serialisedOutputs) ===
    extractOutputHash(txPreimage) commitment."""
    by_name = {b.name: b.value for b in bindings}

    def _is_load_param(ref: str, param: str) -> bool:
        v = by_name.get(ref)
        return v is not None and v.kind == "load_param" and v.name == param

    hashed_witness = set()
    output_hash = set()
    for b in bindings:
        v = b.value
        if v.kind != "call":
            continue
        if v.func == "hash256" and len(v.args or []) == 1 and _is_load_param(
            v.args[0], "_serialisedOutputs"
        ):
            hashed_witness.add(b.name)
        if v.func == "extractOutputHash" and len(v.args or []) == 1 and _is_load_param(
            v.args[0], "txPreimage"
        ):
            output_hash.add(b.name)

    for b in bindings:
        v = b.value
        if v.kind != "bin_op" or v.op != "===":
            continue
        if (v.left in hashed_witness and v.right in output_hash) or (
            v.right in hashed_witness and v.left in output_hash
        ):
            return True
    return False


def _find_if(bindings):
    for b in bindings:
        if b.value.kind == "if":
            return b.value
    return None


_COND_BOND_SOURCE = """
package x

import runar "github.com/icellan/runar/packages/runar-go"

type CondBond struct {
    runar.StatefulSmartContract
    PkhA runar.ByteString `runar:"readonly"`
    PkhB runar.ByteString `runar:"readonly"`
    Bond runar.Bigint     `runar:"readonly"`
}

func (c *CondBond) PayBond(useA runar.Bool) {
    // W2: index 0 is the only one this intrinsic accepts; the branch-binding
    // property under test is about which ARM emits the commitment, not which
    // output index it names.
    if useA {
        runar.RequireOutputP2PKH(0, c.PkhA, c.Bond)
    } else {
        runar.RequireOutputP2PKH(0, c.PkhB, c.Bond)
    }
}
"""


class TestRequireOutputP2PKHBranchBinding:
    def test_both_branches_bind_the_serialised_outputs(self):
        """R-023: a terminal (no state mutation) method whose two arms each
        assert an output must commit ``_serialisedOutputs`` to the preimage's
        hashOutputs on BOTH arms. Only one arm runs on chain, so a missing
        binding on the second arm is an unconstrained-witness bypass."""
        program = _must_lower_go_source(_COND_BOND_SOURCE)
        m = _find_method(program, "payBond")
        assert "_serialisedOutputs" in _param_names(m), _param_names(m)

        # The method is terminal: nothing outside the `if` re-establishes the
        # binding (no state continuation is emitted), so each arm must carry
        # its own.
        assert not _has_output_hash_binding(m.body), (
            "precondition: the top-level body must not already carry the "
            f"binding; got {_binding_kinds(m.body)}"
        )

        node = _find_if(m.body)
        assert node is not None, _binding_kinds(m.body)

        assert _has_output_hash_binding(node.then), (
            "then-arm is missing hash256(_serialisedOutputs) === "
            f"extractOutputHash(txPreimage); got {_binding_kinds(node.then)}"
        )
        assert _has_output_hash_binding(node.else_), (
            "else-arm is missing hash256(_serialisedOutputs) === "
            "extractOutputHash(txPreimage) — the spender may take this path "
            "with an arbitrary _serialisedOutputs witness; got "
            f"{_binding_kinds(node.else_)}"
        )

    def test_single_unconditional_call_emits_exactly_one_binding(self):
        """Control: the straight-line single-call shape is unchanged."""
        source = """
package x

import runar "github.com/icellan/runar/packages/runar-go"

type Cov struct {
    runar.StatefulSmartContract
    BondPKH runar.ByteString `runar:"readonly"`
    Bond    runar.Bigint     `runar:"readonly"`
}

func (c *Cov) PayBond() {
    // W2: index 0 is the only one this intrinsic accepts.
    runar.RequireOutputP2PKH(0, c.BondPKH, c.Bond)
}
"""
        program = _must_lower_go_source(source)
        m = _find_method(program, "payBond")
        assert _has_output_hash_binding(m.body)
        n = sum(
            1
            for b in m.body
            if b.value.kind == "call" and b.value.func == "extractOutputHash"
        )
        assert n == 1, f"expected exactly one output-hash commitment, got {n}"

    def test_two_sequential_calls_still_share_one_binding(self):
        """Control: two calls on the SAME straight-line path still dedup to a
        single commitment — the fix must not turn the dedup off wholesale."""
        source = """
package x

import runar "github.com/icellan/runar/packages/runar-go"

type Cov struct {
    runar.StatefulSmartContract
    BondPKH runar.ByteString `runar:"readonly"`
    Bond    runar.Bigint     `runar:"readonly"`
}

func (c *Cov) PayMulti() {
    // W2: index 0 is the only one this intrinsic accepts; the dedup property
    // under test is per-path, not per-index.
    runar.RequireOutputP2PKH(0, c.BondPKH, c.Bond)
    runar.RequireOutputP2PKH(0, c.BondPKH, c.Bond)
}
"""
        program = _must_lower_go_source(source)
        m = _find_method(program, "payMulti")
        n = sum(
            1
            for b in m.body
            if b.value.kind == "call" and b.value.func == "extractOutputHash"
        )
        assert n == 1, f"expected exactly one output-hash commitment, got {n}"

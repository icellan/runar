"""Tests for the ANF EC optimizer (Pass 4.5).

Covers algebraic simplification rules for EC intrinsic calls, pass-through
behavior for non-EC programs, and dead binding elimination.
"""

from __future__ import annotations

import pytest

from runar_compiler.frontend.anf_optimize import (
    optimize_ec,
    INFINITY_HEX,
    G_HEX,
    CURVE_N,
)
from runar_compiler.ir.types import (
    ANFBinding,
    ANFMethod,
    ANFParam,
    ANFProgram,
    ANFProperty,
    ANFValue,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_program(bindings: list[ANFBinding]) -> ANFProgram:
    """Create a minimal program with a single method containing the given bindings."""
    return ANFProgram(
        contract_name="Test",
        properties=[],
        methods=[
            ANFMethod(
                name="test",
                params=[],
                body=bindings,
                is_public=True,
            ),
        ],
    )


def _load_const_hex(name: str, hex_str: str) -> ANFBinding:
    return ANFBinding(
        name=name,
        value=ANFValue(kind="load_const", const_string=hex_str, raw_value=hex_str),
    )


def _load_const_int(name: str, n: int) -> ANFBinding:
    return ANFBinding(
        name=name,
        value=ANFValue(kind="load_const", const_big_int=n, const_int=n, raw_value=n),
    )


def _call(name: str, func: str, args: list[str]) -> ANFBinding:
    return ANFBinding(
        name=name,
        value=ANFValue(kind="call", func=func, args=args),
    )


def _assert_ref(name: str, value_ref: str) -> ANFBinding:
    return ANFBinding(
        name=name,
        value=ANFValue(kind="assert", value_ref=value_ref, raw_value=value_ref),
    )


def _get_method_body(program: ANFProgram) -> list[ANFBinding]:
    return program.methods[0].body


def _find_binding(bindings: list[ANFBinding], name: str) -> ANFBinding | None:
    for b in bindings:
        if b.name == name:
            return b
    return None


# ---------------------------------------------------------------------------
# Pass-through behavior (no EC ops)
# ---------------------------------------------------------------------------

class TestPassThrough:
    def test_no_ec_ops_unchanged(self):
        """Programs without EC calls pass through without modification."""
        bindings = [
            _load_const_int("t0", 42),
            _load_const_int("t1", 10),
            ANFBinding(
                name="t2",
                value=ANFValue(kind="bin_op", op="+", left="t0", right="t1"),
            ),
            _assert_ref("t3", "t2"),
        ]
        program = _make_program(bindings)
        result = optimize_ec(program)

        body = _get_method_body(result)
        assert len(body) == 4
        assert body[0].name == "t0"
        assert body[1].name == "t1"
        assert body[2].name == "t2"
        assert body[3].name == "t3"

    def test_empty_method_unchanged(self):
        program = _make_program([])
        result = optimize_ec(program)
        assert len(_get_method_body(result)) == 0

    def test_non_ec_call_unchanged(self):
        """Calls to non-EC functions (e.g. hash160) are not optimized."""
        bindings = [
            _load_const_hex("t0", "abcd"),
            _call("t1", "hash160", ["t0"]),
            _assert_ref("t2", "t1"),
        ]
        program = _make_program(bindings)
        result = optimize_ec(program)
        body = _get_method_body(result)
        assert len(body) == 3


# ---------------------------------------------------------------------------
# Rule 1: ecAdd(x, INFINITY) -> x
# ---------------------------------------------------------------------------

class TestRule1EcAddInfinity:
    def test_ec_add_x_infinity(self):
        bindings = [
            _load_const_hex("t0", "ab" * 64),  # some point
            _load_const_hex("t1", INFINITY_HEX),
            _call("t2", "ecAdd", ["t0", "t1"]),
            _assert_ref("t3", "t2"),
        ]
        program = _make_program(bindings)
        result = optimize_ec(program)
        body = _get_method_body(result)

        # t2 should become a @ref: to t0
        t2 = _find_binding(body, "t2")
        assert t2 is not None
        assert t2.value.kind == "load_const"
        assert t2.value.const_string == "@ref:t0"


# ---------------------------------------------------------------------------
# Rule 2: ecAdd(INFINITY, x) -> x
# ---------------------------------------------------------------------------

class TestRule2EcAddInfinityLeft:
    def test_ec_add_infinity_x(self):
        bindings = [
            _load_const_hex("t0", INFINITY_HEX),
            _load_const_hex("t1", "cd" * 64),  # some point
            _call("t2", "ecAdd", ["t0", "t1"]),
            _assert_ref("t3", "t2"),
        ]
        program = _make_program(bindings)
        result = optimize_ec(program)
        body = _get_method_body(result)

        t2 = _find_binding(body, "t2")
        assert t2 is not None
        assert t2.value.kind == "load_const"
        assert t2.value.const_string == "@ref:t1"


# ---------------------------------------------------------------------------
# Rule 3: ecMul(x, 1) -> x
# ---------------------------------------------------------------------------

class TestRule3EcMulByOne:
    def test_ec_mul_x_1(self):
        bindings = [
            _load_const_hex("t0", "ab" * 64),
            _load_const_int("t1", 1),
            _call("t2", "ecMul", ["t0", "t1"]),
            _assert_ref("t3", "t2"),
        ]
        program = _make_program(bindings)
        result = optimize_ec(program)
        body = _get_method_body(result)

        t2 = _find_binding(body, "t2")
        assert t2 is not None
        assert t2.value.kind == "load_const"
        assert t2.value.const_string == "@ref:t0"


# ---------------------------------------------------------------------------
# Rule 4: ecMul(x, 0) -> INFINITY
# ---------------------------------------------------------------------------

class TestRule4EcMulByZero:
    def test_ec_mul_x_0(self):
        bindings = [
            _load_const_hex("t0", "ab" * 64),
            _load_const_int("t1", 0),
            _call("t2", "ecMul", ["t0", "t1"]),
            _assert_ref("t3", "t2"),
        ]
        program = _make_program(bindings)
        result = optimize_ec(program)
        body = _get_method_body(result)

        t2 = _find_binding(body, "t2")
        assert t2 is not None
        assert t2.value.kind == "load_const"
        assert t2.value.const_string == INFINITY_HEX


# ---------------------------------------------------------------------------
# Rule 5: ecMulGen(0) -> INFINITY
# ---------------------------------------------------------------------------

class TestRule5EcMulGenZero:
    def test_ec_mulgen_0(self):
        bindings = [
            _load_const_int("t0", 0),
            _call("t1", "ecMulGen", ["t0"]),
            _assert_ref("t2", "t1"),
        ]
        program = _make_program(bindings)
        result = optimize_ec(program)
        body = _get_method_body(result)

        t1 = _find_binding(body, "t1")
        assert t1 is not None
        assert t1.value.kind == "load_const"
        assert t1.value.const_string == INFINITY_HEX


# ---------------------------------------------------------------------------
# Rule 6: ecMulGen(1) -> G
# ---------------------------------------------------------------------------

class TestRule6EcMulGenOne:
    def test_ec_mulgen_1(self):
        bindings = [
            _load_const_int("t0", 1),
            _call("t1", "ecMulGen", ["t0"]),
            _assert_ref("t2", "t1"),
        ]
        program = _make_program(bindings)
        result = optimize_ec(program)
        body = _get_method_body(result)

        t1 = _find_binding(body, "t1")
        assert t1 is not None
        assert t1.value.kind == "load_const"
        assert t1.value.const_string == G_HEX


# ---------------------------------------------------------------------------
# Rule 7: ecNegate(ecNegate(x)) -> x
# ---------------------------------------------------------------------------

class TestRule7DoubleNegate:
    def test_double_negate(self):
        bindings = [
            _load_const_hex("t0", "ab" * 64),
            _call("t1", "ecNegate", ["t0"]),
            _call("t2", "ecNegate", ["t1"]),
            _assert_ref("t3", "t2"),
        ]
        program = _make_program(bindings)
        result = optimize_ec(program)
        body = _get_method_body(result)

        t2 = _find_binding(body, "t2")
        assert t2 is not None
        assert t2.value.kind == "load_const"
        assert t2.value.const_string == "@ref:t0"


# ---------------------------------------------------------------------------
# Rule 8: ecAdd(x, ecNegate(x)) -> INFINITY
# ---------------------------------------------------------------------------

class TestRule8AddNegate:
    def test_add_self_negate(self):
        bindings = [
            _load_const_hex("t0", "ab" * 64),
            _call("t1", "ecNegate", ["t0"]),
            _call("t2", "ecAdd", ["t0", "t1"]),
            _assert_ref("t3", "t2"),
        ]
        program = _make_program(bindings)
        result = optimize_ec(program)
        body = _get_method_body(result)

        t2 = _find_binding(body, "t2")
        assert t2 is not None
        assert t2.value.kind == "load_const"
        assert t2.value.const_string == INFINITY_HEX


# ---------------------------------------------------------------------------
# Rule 12: ecMul(G, k) -> ecMulGen(k)
# ---------------------------------------------------------------------------

class TestRule12MulGToMulGen:
    def test_mul_g_k(self):
        bindings = [
            _load_const_hex("t0", G_HEX),
            _load_const_int("t1", 42),
            _call("t2", "ecMul", ["t0", "t1"]),
            _assert_ref("t3", "t2"),
        ]
        program = _make_program(bindings)
        result = optimize_ec(program)
        body = _get_method_body(result)

        t2 = _find_binding(body, "t2")
        assert t2 is not None
        assert t2.value.kind == "call"
        assert t2.value.func == "ecMulGen"
        assert t2.value.args == ["t1"]


# ---------------------------------------------------------------------------
# Dead binding elimination
# ---------------------------------------------------------------------------

class TestDeadBindingElimination:
    def test_dead_binding_removed(self):
        """A binding not referenced by anything is eliminated."""
        bindings = [
            _load_const_hex("t0", "ab" * 64),
            _load_const_hex("t1", INFINITY_HEX),
            _call("t2", "ecAdd", ["t0", "t1"]),
            # t2 becomes @ref:t0, making t1 (INFINITY) unreferenced.
            # But t1 is load_const (no side effect), so it gets removed.
            _assert_ref("t3", "t2"),
        ]
        program = _make_program(bindings)
        result = optimize_ec(program)
        body = _get_method_body(result)

        # t1 should be eliminated as dead
        names = [b.name for b in body]
        assert "t1" not in names

    def test_side_effect_bindings_preserved(self):
        """Bindings with side effects (assert, call) are never removed."""
        bindings = [
            _load_const_hex("t0", "ab" * 64),
            _load_const_hex("t1", INFINITY_HEX),
            _call("t2", "ecAdd", ["t0", "t1"]),
            _assert_ref("t3", "t2"),
        ]
        program = _make_program(bindings)
        result = optimize_ec(program)
        body = _get_method_body(result)

        # Assert binding must survive
        names = [b.name for b in body]
        assert "t3" in names


# ---------------------------------------------------------------------------
# Program structure preserved
# ---------------------------------------------------------------------------

class TestStructurePreserved:
    def test_contract_name_preserved(self):
        program = ANFProgram(
            contract_name="MyContract",
            properties=[ANFProperty(name="x", type="bigint")],
            methods=[
                ANFMethod(
                    name="doStuff",
                    params=[ANFParam(name="y", type="bigint")],
                    body=[
                        _load_const_int("t0", 1),
                        _assert_ref("t1", "t0"),
                    ],
                    is_public=True,
                ),
            ],
        )
        result = optimize_ec(program)
        assert result.contract_name == "MyContract"
        assert len(result.properties) == 1
        assert result.properties[0].name == "x"
        assert len(result.methods) == 1
        assert result.methods[0].name == "doStuff"

    def test_multiple_methods_all_optimized(self):
        """Each method is optimized independently."""
        method1 = ANFMethod(
            name="method1",
            params=[],
            body=[
                _load_const_int("t0", 0),
                _call("t1", "ecMulGen", ["t0"]),
                _assert_ref("t2", "t1"),
            ],
            is_public=True,
        )
        method2 = ANFMethod(
            name="method2",
            params=[],
            body=[
                _load_const_int("t0", 1),
                _call("t1", "ecMulGen", ["t0"]),
                _assert_ref("t2", "t1"),
            ],
            is_public=True,
        )
        program = ANFProgram(
            contract_name="Test",
            properties=[],
            methods=[method1, method2],
        )
        result = optimize_ec(program)

        # method1: ecMulGen(0) -> INFINITY
        body1 = result.methods[0].body
        t1_m1 = _find_binding(body1, "t1")
        assert t1_m1 is not None
        assert t1_m1.value.kind == "load_const"
        assert t1_m1.value.const_string == INFINITY_HEX

        # method2: ecMulGen(1) -> G
        body2 = result.methods[1].body
        t1_m2 = _find_binding(body2, "t1")
        assert t1_m2 is not None
        assert t1_m2.value.kind == "load_const"
        assert t1_m2.value.const_string == G_HEX


# ---------------------------------------------------------------------------
# Additional dead binding / side-effect tests
# ---------------------------------------------------------------------------

class TestSideEffectPreservation:
    def test_side_effect_call_binding_preserved(self):
        """A call binding (e.g. checkSig) that is not referenced by any other
        binding should NOT be eliminated — calls have side effects."""
        bindings = [
            ANFBinding(
                name="t0",
                value=ANFValue(kind="load_param", name="sig"),
            ),
            ANFBinding(
                name="t1",
                value=ANFValue(kind="load_param", name="pubKey"),
            ),
            ANFBinding(
                name="t2",
                value=ANFValue(kind="call", func="checkSig", args=["t0", "t1"]),
            ),
            # t2 is never referenced by another binding — but it's a call
            # and calls have side effects, so it must be preserved.
        ]
        program = _make_program(bindings)
        result = optimize_ec(program)
        body = _get_method_body(result)

        names = [b.name for b in body]
        assert "t2" in names, (
            f"expected call binding 't2' to be preserved (side effect), got names: {names}"
        )


# ---------------------------------------------------------------------------
# Chained rule application (Rule 12 then Rule 5)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Rule 10: ecAdd(ecMulGen(k1), ecMulGen(k2)) -> ecMulGen(k1+k2 mod N)
# ---------------------------------------------------------------------------

class TestRule10EcAddMulGen:
    # E9: Rule 10 with concrete integer constants
    def test_e9_ec_add_mulgen_k1_mulgen_k2(self):
        """ecAdd(ecMulGen(2), ecMulGen(3)) → ecMulGen(k1+k2).

        Rule 10: ecAdd(ecMulGen(k1), ecMulGen(k2)) -> ecMulGen(k1+k2 mod N).
        The optimizer rewrites t4 from ecAdd to ecMulGen. The combined constant
        is stored internally (in the optimizer's value map) as a fresh binding
        name (e.g. '__ec_opt_N') rather than added to the binding list directly.
        We verify t4 becomes ecMulGen with exactly 1 arg.
        """
        bindings = [
            _load_const_int("t0", 2),
            _call("t1", "ecMulGen", ["t0"]),
            _load_const_int("t2", 3),
            _call("t3", "ecMulGen", ["t2"]),
            _call("t4", "ecAdd", ["t1", "t3"]),
            _assert_ref("t5", "t4"),
        ]
        program = _make_program(bindings)
        result = optimize_ec(program)
        body = _get_method_body(result)

        t4 = _find_binding(body, "t4")
        assert t4 is not None, "expected t4 binding to be present"
        assert t4.value.kind == "call", (
            f"expected t4 to be a 'call' after Rule 10, got kind='{t4.value.kind}'"
        )
        assert t4.value.func == "ecMulGen", (
            f"expected t4 func to be 'ecMulGen' after Rule 10, got '{t4.value.func}'"
        )
        # The single arg should be a constant reference (k1+k2)
        assert len(t4.value.args) == 1, (
            f"expected ecMulGen to have 1 arg, got {len(t4.value.args)}"
        )
        # The arg is a fresh binding name whose value is 5 = (2+3) % CURVE_N.
        # The fresh binding is stored in the optimizer's internal value map, not in
        # the body list, so we can only verify the structural transformation here.
        combined_arg = t4.value.args[0]
        assert isinstance(combined_arg, str) and len(combined_arg) > 0, (
            f"expected ecMulGen arg to be a non-empty binding name, got: {combined_arg!r}"
        )


class TestChainedRules:
    def test_chained_rules_12_then_5(self):
        """ecMul(G, 0) should optimize via Rule 12 (ecMul(G,k) -> ecMulGen(k))
        then Rule 5 (ecMulGen(0) -> INFINITY) to produce INFINITY."""
        bindings = [
            _load_const_hex("t0", G_HEX),
            _load_const_int("t1", 0),
            _call("t2", "ecMul", ["t0", "t1"]),
            _assert_ref("t3", "t2"),
        ]
        program = _make_program(bindings)
        result = optimize_ec(program)
        body = _get_method_body(result)

        t2 = _find_binding(body, "t2")
        assert t2 is not None
        assert t2.value.kind == "load_const", (
            f"expected t2 to be load_const after chained Rule 12+5, got kind='{t2.value.kind}'"
        )
        assert t2.value.const_string == INFINITY_HEX, (
            f"expected t2 to be INFINITY after chained rules, got '{t2.value.const_string}'"
        )

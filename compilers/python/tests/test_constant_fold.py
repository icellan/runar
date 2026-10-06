"""Tests for the ANF constant folding pass.

Mirrors the Rust constant_fold.rs tests and Go constant_fold_test.go.
"""

from __future__ import annotations

import json

from runar_compiler.ir.types import (
    ANFBinding,
    ANFMethod,
    ANFParam,
    ANFProgram,
    ANFProperty,
    ANFValue,
)
from runar_compiler.frontend.constant_fold import fold_constants


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_program(methods: list[ANFMethod]) -> ANFProgram:
    return ANFProgram(contract_name="Test", properties=[], methods=methods)


def _make_method(name: str, body: list[ANFBinding]) -> ANFMethod:
    return ANFMethod(name=name, params=[], body=body, is_public=True)


def _b(name: str, value: ANFValue) -> ANFBinding:
    return ANFBinding(name=name, value=value)


def _mk_int(n: int) -> ANFValue:
    return ANFValue(kind="load_const", raw_value=json.dumps(n), const_big_int=n, const_int=n)


def _mk_bool(v: bool) -> ANFValue:
    return ANFValue(kind="load_const", raw_value=json.dumps(v), const_bool=v)


def _mk_str(s: str) -> ANFValue:
    return ANFValue(kind="load_const", raw_value=json.dumps(s), const_string=s)


def _bin_op(op: str, left: str, right: str) -> ANFValue:
    return ANFValue(kind="bin_op", op=op, left=left, right=right)


def _unary_op(op: str, operand: str) -> ANFValue:
    return ANFValue(kind="unary_op", op=op, operand=operand)


def _load_param(name: str) -> ANFValue:
    return ANFValue(kind="load_param", name=name)


def _call_func(name: str, args: list[str]) -> ANFValue:
    return ANFValue(kind="call", func=name, args=args)


def _assert_load_const_int(value: ANFValue, expected: int) -> None:
    assert value.kind == "load_const", f"expected load_const, got {value.kind}"
    actual = value.const_big_int if value.const_big_int is not None else value.const_int
    assert actual == expected, f"expected {expected}, got {actual}"


def _assert_load_const_bool(value: ANFValue, expected: bool) -> None:
    assert value.kind == "load_const", f"expected load_const, got {value.kind}"
    assert value.const_bool == expected, f"expected {expected}, got {value.const_bool}"


def _assert_load_const_str(value: ANFValue, expected: str) -> None:
    assert value.kind == "load_const", f"expected load_const, got {value.kind}"
    assert value.const_string == expected, f"expected '{expected}', got '{value.const_string}'"


def _assert_not_folded(value: ANFValue, expected_kind: str) -> None:
    assert value.kind == expected_kind, f"expected {expected_kind}, got {value.kind}"


# ---------------------------------------------------------------------------
# 1. Binary operations on integers
# ---------------------------------------------------------------------------

class TestBinaryOps:
    def test_fold_addition(self):
        p = _make_program([_make_method("m", [
            _b("t0", _mk_int(10)),
            _b("t1", _mk_int(20)),
            _b("t2", _bin_op("+", "t0", "t1")),
        ])])
        r = fold_constants(p)
        _assert_load_const_int(r.methods[0].body[2].value, 30)

    def test_fold_subtraction(self):
        p = _make_program([_make_method("m", [
            _b("t0", _mk_int(50)),
            _b("t1", _mk_int(20)),
            _b("t2", _bin_op("-", "t0", "t1")),
        ])])
        r = fold_constants(p)
        _assert_load_const_int(r.methods[0].body[2].value, 30)

    def test_fold_multiplication(self):
        p = _make_program([_make_method("m", [
            _b("t0", _mk_int(6)),
            _b("t1", _mk_int(7)),
            _b("t2", _bin_op("*", "t0", "t1")),
        ])])
        r = fold_constants(p)
        _assert_load_const_int(r.methods[0].body[2].value, 42)

    def test_fold_division(self):
        p = _make_program([_make_method("m", [
            _b("t0", _mk_int(100)),
            _b("t1", _mk_int(4)),
            _b("t2", _bin_op("/", "t0", "t1")),
        ])])
        r = fold_constants(p)
        _assert_load_const_int(r.methods[0].body[2].value, 25)

    def test_no_fold_div_by_zero(self):
        p = _make_program([_make_method("m", [
            _b("t0", _mk_int(100)),
            _b("t1", _mk_int(0)),
            _b("t2", _bin_op("/", "t0", "t1")),
        ])])
        r = fold_constants(p)
        _assert_not_folded(r.methods[0].body[2].value, "bin_op")

    def test_fold_modulo(self):
        p = _make_program([_make_method("m", [
            _b("t0", _mk_int(10)),
            _b("t1", _mk_int(3)),
            _b("t2", _bin_op("%", "t0", "t1")),
        ])])
        r = fold_constants(p)
        _assert_load_const_int(r.methods[0].body[2].value, 1)

    def test_no_fold_mod_by_zero(self):
        p = _make_program([_make_method("m", [
            _b("t0", _mk_int(100)),
            _b("t1", _mk_int(0)),
            _b("t2", _bin_op("%", "t0", "t1")),
        ])])
        r = fold_constants(p)
        _assert_not_folded(r.methods[0].body[2].value, "bin_op")

    def test_fold_negative_division_truncates_toward_zero(self):
        """Python // floors, but we need truncation toward zero like JS BigInt."""
        p = _make_program([_make_method("m", [
            _b("t0", _mk_int(-7)),
            _b("t1", _mk_int(2)),
            _b("t2", _bin_op("/", "t0", "t1")),
        ])])
        r = fold_constants(p)
        # JS BigInt: -7n / 2n = -3n (truncate toward zero)
        # Python //: -7 // 2 = -4 (floor)
        _assert_load_const_int(r.methods[0].body[2].value, -3)

    def test_fold_negative_modulo_sign_follows_dividend(self):
        """Modulo sign should follow dividend (JS BigInt semantics)."""
        p = _make_program([_make_method("m", [
            _b("t0", _mk_int(-7)),
            _b("t1", _mk_int(2)),
            _b("t2", _bin_op("%", "t0", "t1")),
        ])])
        r = fold_constants(p)
        # JS BigInt: -7n % 2n = -1n (sign follows dividend)
        # Python %: -7 % 2 = 1 (sign follows divisor)
        _assert_load_const_int(r.methods[0].body[2].value, -1)

    def test_fold_comparisons(self):
        cases = [
            ("===", 5, 5, True),
            ("!==", 5, 5, False),
            ("<", 5, 6, True),
            (">", 6, 5, True),
            ("<=", 5, 5, True),
            (">=", 5, 5, True),
        ]
        for op, a, b_val, expected in cases:
            p = _make_program([_make_method("m", [
                _b("t0", _mk_int(a)),
                _b("t1", _mk_int(b_val)),
                _b("t2", _bin_op(op, "t0", "t1")),
            ])])
            r = fold_constants(p)
            _assert_load_const_bool(r.methods[0].body[2].value, expected)


# ---------------------------------------------------------------------------
# 2. Shift operators
# ---------------------------------------------------------------------------

class TestShiftOps:
    def test_no_fold_shifts(self):
        # OP_LSHIFT/OP_RSHIFT operate on the operands' raw script-number bytes,
        # preserving byte length -- 255 << 1 is 254 on-chain, not 510. Folding
        # with native int would bake a wrong constant into the deployed script,
        # so the folder must leave these as bin_ops for the runtime opcode (the
        # SDK ANF interpreter models the same byte semantics).
        p = _make_program([_make_method("m", [
            _b("t0", _mk_int(255)),
            _b("t1", _mk_int(1)),
            _b("t2", _bin_op("<<", "t0", "t1")),
            _b("t3", _bin_op(">>", "t0", "t1")),
        ])])
        r = fold_constants(p)
        _assert_not_folded(r.methods[0].body[2].value, "bin_op")
        _assert_not_folded(r.methods[0].body[3].value, "bin_op")

    def test_no_fold_negative_shift(self):
        # Subsumed by the rule above, but kept as an explicit regression anchor.
        p = _make_program([_make_method("m", [
            _b("t0", _mk_int(-8)),
            _b("t1", _mk_int(1)),
            _b("t2", _bin_op(">>", "t0", "t1")),
        ])])
        r = fold_constants(p)
        _assert_not_folded(r.methods[0].body[2].value, "bin_op")


# ---------------------------------------------------------------------------
# 3. Bitwise operators
# ---------------------------------------------------------------------------

class TestBitwiseOps:
    def test_no_fold_bitwise(self):
        # OP_AND/OP_OR/OP_XOR require equal-length operand bytes and operate
        # bytewise -- the numeric fold (e.g. 255 & 1 == 1) disagrees with the
        # on-chain result (255 & 1 ABORTS on a length mismatch). Never fold;
        # emit the opcode so runtime byte-array semantics govern.
        p = _make_program([_make_method("m", [
            _b("t0", _mk_int(0b1100)),
            _b("t1", _mk_int(0b1010)),
            _b("t2", _bin_op("&", "t0", "t1")),
            _b("t3", _bin_op("|", "t0", "t1")),
            _b("t4", _bin_op("^", "t0", "t1")),
        ])])
        r = fold_constants(p)
        _assert_not_folded(r.methods[0].body[2].value, "bin_op")
        _assert_not_folded(r.methods[0].body[3].value, "bin_op")
        _assert_not_folded(r.methods[0].body[4].value, "bin_op")


# ---------------------------------------------------------------------------
# 4. Boolean operations
# ---------------------------------------------------------------------------

class TestBooleanOps:
    def test_fold_boolean_and_or(self):
        p = _make_program([_make_method("m", [
            _b("t0", _mk_bool(True)),
            _b("t1", _mk_bool(False)),
            _b("t2", _bin_op("&&", "t0", "t1")),
            _b("t3", _bin_op("||", "t0", "t1")),
        ])])
        r = fold_constants(p)
        _assert_load_const_bool(r.methods[0].body[2].value, False)
        _assert_load_const_bool(r.methods[0].body[3].value, True)

    def test_fold_boolean_equality(self):
        p = _make_program([_make_method("m", [
            _b("t0", _mk_bool(True)),
            _b("t1", _mk_bool(True)),
            _b("t2", _bin_op("===", "t0", "t1")),
        ])])
        r = fold_constants(p)
        _assert_load_const_bool(r.methods[0].body[2].value, True)


# ---------------------------------------------------------------------------
# 5. String (ByteString) operations
# ---------------------------------------------------------------------------

class TestStringOps:
    def test_fold_hex_concat(self):
        p = _make_program([_make_method("m", [
            _b("t0", _mk_str("ab")),
            _b("t1", _mk_str("cd")),
            _b("t2", _bin_op("+", "t0", "t1")),
        ])])
        r = fold_constants(p)
        _assert_load_const_str(r.methods[0].body[2].value, "abcd")

    def test_no_fold_invalid_hex_concat(self):
        p = _make_program([_make_method("m", [
            _b("t0", _mk_str("aabb")),
            _b("t1", _mk_str("zzzz")),
            _b("t2", _bin_op("+", "t0", "t1")),
        ])])
        r = fold_constants(p)
        _assert_not_folded(r.methods[0].body[2].value, "bin_op")

    def test_fold_string_equality(self):
        p = _make_program([_make_method("m", [
            _b("t0", _mk_str("abc")),
            _b("t1", _mk_str("abc")),
            _b("t2", _bin_op("===", "t0", "t1")),
        ])])
        r = fold_constants(p)
        _assert_load_const_bool(r.methods[0].body[2].value, True)


# ---------------------------------------------------------------------------
# 6. Unary operations
# ---------------------------------------------------------------------------

class TestUnaryOps:
    def test_fold_boolean_negation(self):
        p = _make_program([_make_method("m", [
            _b("t0", _mk_bool(True)),
            _b("t1", _unary_op("!", "t0")),
        ])])
        r = fold_constants(p)
        _assert_load_const_bool(r.methods[0].body[1].value, False)

    def test_fold_int_negation(self):
        p = _make_program([_make_method("m", [
            _b("t0", _mk_int(42)),
            _b("t1", _unary_op("-", "t0")),
        ])])
        r = fold_constants(p)
        _assert_load_const_int(r.methods[0].body[1].value, -42)

    def test_no_fold_bitwise_not(self):
        # OP_INVERT flips the operand's script-number bytes, not native ~n
        # (~5 is -122 on-chain, not -6). Never fold; emit the opcode.
        p = _make_program([_make_method("m", [
            _b("t0", _mk_int(5)),
            _b("t1", _unary_op("~", "t0")),
        ])])
        r = fold_constants(p)
        _assert_not_folded(r.methods[0].body[1].value, "unary_op")

    def test_fold_bang_on_zero(self):
        """!0n should produce True (boolean), not 1."""
        p = _make_program([_make_method("m", [
            _b("t0", _mk_int(0)),
            _b("t1", _unary_op("!", "t0")),
        ])])
        r = fold_constants(p)
        _assert_load_const_bool(r.methods[0].body[1].value, True)


# ---------------------------------------------------------------------------
# 7. Constant propagation
# ---------------------------------------------------------------------------

class TestConstantPropagation:
    def test_propagation_chain(self):
        p = _make_program([_make_method("m", [
            _b("t0", _mk_int(10)),
            _b("t1", _mk_int(20)),
            _b("t2", _bin_op("+", "t0", "t1")),
            _b("t3", _mk_int(12)),
            _b("t4", _bin_op("+", "t2", "t3")),
        ])])
        r = fold_constants(p)
        _assert_load_const_int(r.methods[0].body[4].value, 42)

    def test_no_fold_with_param(self):
        p = _make_program([_make_method("m", [
            _b("t0", _load_param("x")),
            _b("t1", _mk_int(5)),
            _b("t2", _bin_op("+", "t0", "t1")),
        ])])
        r = fold_constants(p)
        _assert_not_folded(r.methods[0].body[2].value, "bin_op")


# ---------------------------------------------------------------------------
# 8. If-branch folding
# ---------------------------------------------------------------------------

class TestIfBranchFolding:
    # A statically-known condition must NOT blank the untaken arm.
    #
    # The folder used to return an empty arm while leaving the `if` node itself
    # in place.  An arm is not a free-floating binding list -- it carries the
    # stack-shape contract ANF lowering builds (the __merge$<i> result block for
    # K>=2 merged locals) and stack lowering consumes.  Erasing one arm made
    # _lower_if register ONE stack slot for K physical results, which at K=2
    # silently miscompiled the guard (the deployed script accepted spends the
    # source rejects) and at K=1 rejected source that compiles with folding
    # disabled.
    def test_keeps_both_arms_when_condition_known_true(self):
        p = _make_program([_make_method("m", [
            _b("t0", _mk_bool(True)),
            _b("t1", ANFValue(
                kind="if",
                cond="t0",
                then=[_b("t2", _mk_int(42))],
                else_=[_b("t3", _mk_int(99))],
            )),
        ])])
        r = fold_constants(p)
        v = r.methods[0].body[1].value
        assert v.kind == "if"
        assert len(v.then) == 1
        assert len(v.else_) == 1

    def test_keeps_both_arms_when_condition_known_false(self):
        p = _make_program([_make_method("m", [
            _b("t0", _mk_bool(False)),
            _b("t1", ANFValue(
                kind="if",
                cond="t0",
                then=[_b("t2", _mk_int(42))],
                else_=[_b("t3", _mk_int(99))],
            )),
        ])])
        r = fold_constants(p)
        v = r.methods[0].body[1].value
        assert v.kind == "if"
        assert len(v.then) == 1
        assert len(v.else_) == 1

    # A statically-known condition must not leak an arm's constants into the
    # enclosing environment either: the `if` survives the pass, so both arms are
    # still emitted and either can run.
    def test_does_not_propagate_taken_arm_constants(self):
        p = _make_program([_make_method("m", [
            _b("t0", _mk_bool(True)),
            _b("t1", ANFValue(
                kind="if",
                cond="t0",
                then=[_b("x", _mk_int(42))],
                else_=[_b("x", _mk_int(99))],
            )),
            _b("t2", _bin_op("+", "x", "t0")),
        ])])
        r = fold_constants(p)
        assert r.methods[0].body[2].value.kind == "bin_op"

    def test_fold_constants_in_branches(self):
        p = _make_program([_make_method("m", [
            _b("t0", _load_param("flag")),
            _b("t1", _mk_int(5)),
            _b("t2", _mk_int(3)),
            _b("t3", ANFValue(
                kind="if",
                cond="t0",
                then=[_b("t4", _bin_op("+", "t1", "t2"))],
                else_=[_b("t5", _bin_op("-", "t1", "t2"))],
            )),
        ])])
        r = fold_constants(p)
        v = r.methods[0].body[3].value
        assert v.kind == "if"
        _assert_load_const_int(v.then[0].value, 8)
        _assert_load_const_int(v.else_[0].value, 2)


# ---------------------------------------------------------------------------
# 9. Loop folding
# ---------------------------------------------------------------------------

class TestLoopFolding:
    def test_fold_constants_in_loop(self):
        p = _make_program([_make_method("m", [
            _b("t0", _mk_int(10)),
            _b("t1", _mk_int(20)),
            _b("t2", ANFValue(
                kind="loop",
                count=5,
                body=[_b("t3", _bin_op("+", "t0", "t1"))],
                iter_var="i",
            )),
        ])])
        r = fold_constants(p)
        v = r.methods[0].body[2].value
        assert v.kind == "loop"
        _assert_load_const_int(v.body[0].value, 30)


# ---------------------------------------------------------------------------
# 10. Non-foldable values pass through
# ---------------------------------------------------------------------------

class TestPassthrough:
    def test_load_param_unchanged(self):
        p = _make_program([_make_method("m", [
            _b("t0", _load_param("x")),
        ])])
        r = fold_constants(p)
        _assert_not_folded(r.methods[0].body[0].value, "load_param")

    def test_load_prop_unchanged(self):
        p = _make_program([_make_method("m", [
            _b("t0", ANFValue(kind="load_prop", name="pk")),
        ])])
        r = fold_constants(p)
        _assert_not_folded(r.methods[0].body[0].value, "load_prop")

    def test_assert_unchanged(self):
        p = _make_program([_make_method("m", [
            _b("t0", _mk_bool(True)),
            _b("t1", ANFValue(kind="assert", value_ref="t0")),
        ])])
        r = fold_constants(p)
        assert r.methods[0].body[1].value.kind == "assert"


# ---------------------------------------------------------------------------
# 11. Pure math builtin folding
# ---------------------------------------------------------------------------

class TestBuiltinFolding:
    def test_fold_abs(self):
        p = _make_program([_make_method("m", [
            _b("t0", _mk_int(-5)),
            _b("t1", _call_func("abs", ["t0"])),
        ])])
        r = fold_constants(p)
        _assert_load_const_int(r.methods[0].body[1].value, 5)

    def test_fold_min(self):
        p = _make_program([_make_method("m", [
            _b("t0", _mk_int(3)),
            _b("t1", _mk_int(7)),
            _b("t2", _call_func("min", ["t0", "t1"])),
        ])])
        r = fold_constants(p)
        _assert_load_const_int(r.methods[0].body[2].value, 3)

    def test_fold_max(self):
        p = _make_program([_make_method("m", [
            _b("t0", _mk_int(3)),
            _b("t1", _mk_int(7)),
            _b("t2", _call_func("max", ["t0", "t1"])),
        ])])
        r = fold_constants(p)
        _assert_load_const_int(r.methods[0].body[2].value, 7)

    def test_fold_safediv(self):
        p = _make_program([_make_method("m", [
            _b("t0", _mk_int(10)),
            _b("t1", _mk_int(3)),
            _b("t2", _call_func("safediv", ["t0", "t1"])),
        ])])
        r = fold_constants(p)
        _assert_load_const_int(r.methods[0].body[2].value, 3)

    def test_no_fold_safediv_by_zero(self):
        p = _make_program([_make_method("m", [
            _b("t0", _mk_int(10)),
            _b("t1", _mk_int(0)),
            _b("t2", _call_func("safediv", ["t0", "t1"])),
        ])])
        r = fold_constants(p)
        _assert_not_folded(r.methods[0].body[2].value, "call")

    def test_fold_safemod(self):
        p = _make_program([_make_method("m", [
            _b("t0", _mk_int(10)),
            _b("t1", _mk_int(3)),
            _b("t2", _call_func("safemod", ["t0", "t1"])),
        ])])
        r = fold_constants(p)
        _assert_load_const_int(r.methods[0].body[2].value, 1)

    def test_fold_clamp(self):
        p = _make_program([_make_method("m", [
            _b("t0", _mk_int(15)),
            _b("t1", _mk_int(0)),
            _b("t2", _mk_int(10)),
            _b("t3", _call_func("clamp", ["t0", "t1", "t2"])),
        ])])
        r = fold_constants(p)
        _assert_load_const_int(r.methods[0].body[3].value, 10)

    def test_fold_sign(self):
        p = _make_program([_make_method("m", [
            _b("t0", _mk_int(-42)),
            _b("t1", _call_func("sign", ["t0"])),
        ])])
        r = fold_constants(p)
        _assert_load_const_int(r.methods[0].body[1].value, -1)

    def test_fold_pow(self):
        p = _make_program([_make_method("m", [
            _b("t0", _mk_int(2)),
            _b("t1", _mk_int(10)),
            _b("t2", _call_func("pow", ["t0", "t1"])),
        ])])
        r = fold_constants(p)
        _assert_load_const_int(r.methods[0].body[2].value, 1024)

    def test_fold_muldiv(self):
        p = _make_program([_make_method("m", [
            _b("t0", _mk_int(10)),
            _b("t1", _mk_int(20)),
            _b("t2", _mk_int(3)),
            _b("t3", _call_func("mulDiv", ["t0", "t1", "t2"])),
        ])])
        r = fold_constants(p)
        _assert_load_const_int(r.methods[0].body[3].value, 66)

    def test_fold_percent_of(self):
        p = _make_program([_make_method("m", [
            _b("t0", _mk_int(1000)),
            _b("t1", _mk_int(500)),
            _b("t2", _call_func("percentOf", ["t0", "t1"])),
        ])])
        r = fold_constants(p)
        _assert_load_const_int(r.methods[0].body[2].value, 50)

    def test_fold_sqrt(self):
        p = _make_program([_make_method("m", [
            _b("t0", _mk_int(144)),
            _b("t1", _call_func("sqrt", ["t0"])),
        ])])
        r = fold_constants(p)
        _assert_load_const_int(r.methods[0].body[1].value, 12)

    def test_fold_gcd(self):
        p = _make_program([_make_method("m", [
            _b("t0", _mk_int(12)),
            _b("t1", _mk_int(8)),
            _b("t2", _call_func("gcd", ["t0", "t1"])),
        ])])
        r = fold_constants(p)
        _assert_load_const_int(r.methods[0].body[2].value, 4)

    def test_fold_log2(self):
        p = _make_program([_make_method("m", [
            _b("t0", _mk_int(256)),
            _b("t1", _call_func("log2", ["t0"])),
        ])])
        r = fold_constants(p)
        _assert_load_const_int(r.methods[0].body[1].value, 8)

    def test_fold_bool_builtin(self):
        p = _make_program([_make_method("m", [
            _b("t0", _mk_int(0)),
            _b("t1", _call_func("bool", ["t0"])),
        ])])
        r = fold_constants(p)
        _assert_load_const_bool(r.methods[0].body[1].value, False)

    def test_fold_divmod(self):
        p = _make_program([_make_method("m", [
            _b("t0", _mk_int(10)),
            _b("t1", _mk_int(3)),
            _b("t2", _call_func("divmod", ["t0", "t1"])),
        ])])
        r = fold_constants(p)
        _assert_load_const_int(r.methods[0].body[2].value, 3)


# ---------------------------------------------------------------------------
# 12. Cross-type equality
# ---------------------------------------------------------------------------

class TestCrossTypeEquality:
    def test_cross_type_equality(self):
        p = _make_program([_make_method("m", [
            _b("t0", _mk_int(1)),
            _b("t1", _mk_bool(True)),
            _b("t2", _bin_op("===", "t0", "t1")),
            _b("t3", _bin_op("!==", "t0", "t1")),
        ])])
        r = fold_constants(p)
        _assert_load_const_bool(r.methods[0].body[2].value, False)
        _assert_load_const_bool(r.methods[0].body[3].value, True)


# ---------------------------------------------------------------------------
# 13. @ref: aliases should not be treated as constants
# ---------------------------------------------------------------------------

class TestRefAliases:
    def test_ref_alias_not_folded(self):
        """@ref: prefixed strings in load_const should not be treated as constants."""
        p = _make_program([_make_method("m", [
            _b("t0", _mk_int(5)),
            _b("x", ANFValue(kind="load_const", raw_value='"@ref:t0"', const_string="@ref:t0")),
            _b("t1", _mk_int(3)),
            _b("t2", _bin_op("+", "x", "t1")),
        ])])
        r = fold_constants(p)
        # x is a @ref: alias, not a real constant, so t2 should not be folded
        _assert_not_folded(r.methods[0].body[3].value, "bin_op")


# ---------------------------------------------------------------------------
# 14. Large integer division (float precision regression tests)
# ---------------------------------------------------------------------------

class TestLargeIntegerPrecision:
    def test_fold_large_integer_division_no_precision_loss(self):
        """Verify no precision loss for integers > 2^53 (float64 mantissa limit)."""
        # 2^60 + 1 = 1152921504606846977
        # Correct: 1152921504606846977 // 3 = 384307168202282325
        # Broken float: int((2**60+1) / 3) = 384307168202282368
        a = 2**60 + 1
        b = 3
        expected = 384307168202282325
        prog = _make_program([_make_method("m", [
            _b("t0", _mk_int(a)),
            _b("t1", _mk_int(b)),
            _b("t2", _bin_op("/", "t0", "t1")),
        ])])
        result = fold_constants(prog)
        _assert_load_const_int(result.methods[0].body[2].value, expected)

    def test_fold_large_negative_division_no_precision_loss(self):
        """Large negative division must not lose precision."""
        a = -(2**60 + 1)
        b = 3
        expected = -384307168202282325
        prog = _make_program([_make_method("m", [
            _b("t0", _mk_int(a)),
            _b("t1", _mk_int(b)),
            _b("t2", _bin_op("/", "t0", "t1")),
        ])])
        result = fold_constants(prog)
        _assert_load_const_int(result.methods[0].body[2].value, expected)

    def test_fold_large_modulo_no_precision_loss(self):
        """Modulo with large values must use integer arithmetic."""
        a = 2**60 + 1
        b = 3
        # 1152921504606846977 % 3 = 1152921504606846977 - 384307168202282325 * 3 = 2
        expected = 2
        prog = _make_program([_make_method("m", [
            _b("t0", _mk_int(a)),
            _b("t1", _mk_int(b)),
            _b("t2", _bin_op("%", "t0", "t1")),
        ])])
        result = fold_constants(prog)
        _assert_load_const_int(result.methods[0].body[2].value, expected)

    def test_fold_safediv_large_no_precision_loss(self):
        """safediv with large values must not lose precision."""
        a = 2**60 + 1
        b = 3
        expected = 384307168202282325
        prog = _make_program([_make_method("m", [
            _b("t0", _mk_int(a)),
            _b("t1", _mk_int(b)),
            _b("t2", _call_func("safediv", ["t0", "t1"])),
        ])])
        result = fold_constants(prog)
        _assert_load_const_int(result.methods[0].body[2].value, expected)

    def test_fold_divmod_large_no_precision_loss(self):
        """divmod with large values must not lose precision."""
        a = 2**60 + 1
        b = 3
        expected = 384307168202282325
        prog = _make_program([_make_method("m", [
            _b("t0", _mk_int(a)),
            _b("t1", _mk_int(b)),
            _b("t2", _call_func("divmod", ["t0", "t1"])),
        ])])
        result = fold_constants(prog)
        _assert_load_const_int(result.methods[0].body[2].value, expected)

    def test_fold_division_truncates_toward_zero(self):
        """Verify -7/2 = -3 (truncate toward zero), not -4 (Python floor division)."""
        prog = _make_program([_make_method("m", [
            _b("t0", _mk_int(-7)),
            _b("t1", _mk_int(2)),
            _b("t2", _bin_op("/", "t0", "t1")),
        ])])
        result = fold_constants(prog)
        _assert_load_const_int(result.methods[0].body[2].value, -3)

    def test_fold_modulo_negative_dividend(self):
        """Verify -7 % 2 = -1 (sign follows dividend), not 1 (Python floor mod)."""
        prog = _make_program([_make_method("m", [
            _b("t0", _mk_int(-7)),
            _b("t1", _mk_int(2)),
            _b("t2", _bin_op("%", "t0", "t1")),
        ])])
        result = fold_constants(prog)
        _assert_load_const_int(result.methods[0].body[2].value, -1)


# ---------------------------------------------------------------------------
# N-029: folded values must be what the emitted script computes
# ---------------------------------------------------------------------------
# clamp lowers to `<v> <lo> OP_MAX <hi> OP_MIN` = min(max(v, lo), hi), which
# differs from max(lo, min(v, hi)) once lo > hi; log2 unrolls 64 halvings and
# gcd 256 Euclid steps, so past those the script returns a saturated / partial
# value and the folder must decline. Expected values were executed on @bsv/sdk
# Spend.validate by
# packages/runar-testing/src/__tests__/n029-fold-builtin-script-parity.test.ts.
# Proves the Python folder's value/decline decisions; not the script itself.

def _n029_fib(n: int) -> int:
    a, c = 0, 1
    for _ in range(n):
        a, c = c, a + c
    return a


def _n029_fold(args: list[int], func: str) -> ANFValue:
    body = [_b(f"t{i}", _mk_int(a)) for i, a in enumerate(args)]
    body.append(_b("r", _call_func(func, [f"t{i}" for i in range(len(args))])))
    r = fold_constants(_make_program([_make_method("m", body)]))
    return r.methods[0].body[-1].value


class TestN029FoldMatchesScript:
    def test_clamp_lo_above_hi_matches_script(self):
        _assert_load_const_int(_n029_fold([5, 10, 0], "clamp"), 0)
        _assert_load_const_int(_n029_fold([0, 3, -3], "clamp"), -3)
        _assert_load_const_int(_n029_fold([-20, 10, 0], "clamp"), 0)

    def test_log2_declines_past_64_halvings(self):
        _assert_load_const_int(_n029_fold([1 << 64], "log2"), 64)
        _assert_load_const_int(_n029_fold([(1 << 65) - 1], "log2"), 64)
        _assert_not_folded(_n029_fold([1 << 65], "log2"), "call")
        _assert_not_folded(_n029_fold([1 << 70], "log2"), "call")

    def test_gcd_declines_past_256_steps(self):
        _assert_load_const_int(_n029_fold([_n029_fib(258), _n029_fib(257)], "gcd"), 1)
        _assert_not_folded(_n029_fold([_n029_fib(259), _n029_fib(258)], "gcd"), "call")
        _assert_not_folded(_n029_fold([_n029_fib(300), _n029_fib(299)], "gcd"), "call")

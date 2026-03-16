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
    def test_fold_left_shift(self):
        p = _make_program([_make_method("m", [
            _b("t0", _mk_int(1)),
            _b("t1", _mk_int(3)),
            _b("t2", _bin_op("<<", "t0", "t1")),
        ])])
        r = fold_constants(p)
        _assert_load_const_int(r.methods[0].body[2].value, 8)

    def test_fold_right_shift(self):
        p = _make_program([_make_method("m", [
            _b("t0", _mk_int(16)),
            _b("t1", _mk_int(2)),
            _b("t2", _bin_op(">>", "t0", "t1")),
        ])])
        r = fold_constants(p)
        _assert_load_const_int(r.methods[0].body[2].value, 4)

    def test_no_fold_negative_shift(self):
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
    def test_fold_bitwise(self):
        # AND: 0b1100 & 0b1010 = 0b1000 = 8
        p = _make_program([_make_method("m", [
            _b("t0", _mk_int(0b1100)),
            _b("t1", _mk_int(0b1010)),
            _b("t2", _bin_op("&", "t0", "t1")),
            _b("t3", _bin_op("|", "t0", "t1")),
            _b("t4", _bin_op("^", "t0", "t1")),
        ])])
        r = fold_constants(p)
        _assert_load_const_int(r.methods[0].body[2].value, 8)
        _assert_load_const_int(r.methods[0].body[3].value, 14)
        _assert_load_const_int(r.methods[0].body[4].value, 6)


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

    def test_fold_bitwise_not(self):
        p = _make_program([_make_method("m", [
            _b("t0", _mk_int(0)),
            _b("t1", _unary_op("~", "t0")),
        ])])
        r = fold_constants(p)
        _assert_load_const_int(r.methods[0].body[1].value, -1)

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
    def test_fold_true_branch(self):
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
        assert len(v.else_) == 0

    def test_fold_false_branch(self):
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
        assert len(v.then) == 0
        assert len(v.else_) == 1

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

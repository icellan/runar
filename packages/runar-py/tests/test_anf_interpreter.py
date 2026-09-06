"""Tests for runar.sdk.anf_interpreter — state-transition computation.

Mirrors TS/Rust ANF interpreter tests. Verifies that compute_new_state correctly
walks ANF IR bindings and produces updated state.
"""

from __future__ import annotations

import pytest
from runar.sdk.anf_interpreter import compute_new_state


# ---------------------------------------------------------------------------
# Helpers: minimal ANF IR dicts
# ---------------------------------------------------------------------------

def _counter_anf() -> dict:
    """ANF IR for a simple Counter with increment and decrement methods."""
    return {
        "contractName": "Counter",
        "properties": [
            {"name": "count", "type": "bigint", "readonly": False},
        ],
        "methods": [
            {
                "name": "constructor",
                "params": [{"name": "count", "type": "bigint"}],
                "body": [],
                "isPublic": False,
            },
            {
                "name": "increment",
                "params": [
                    {"name": "txPreimage", "type": "SigHashPreimage"},
                    {"name": "_changePKH", "type": "Addr"},
                    {"name": "_changeAmount", "type": "bigint"},
                ],
                "body": [
                    {"name": "t0", "value": {"kind": "load_prop", "name": "count"}},
                    {"name": "t1", "value": {"kind": "load_const", "value": 1}},
                    {"name": "t2", "value": {"kind": "bin_op", "op": "+", "left": "t0", "right": "t1"}},
                    {"name": "t3", "value": {"kind": "update_prop", "name": "count", "value": "t2"}},
                ],
                "isPublic": True,
            },
            {
                "name": "decrement",
                "params": [
                    {"name": "txPreimage", "type": "SigHashPreimage"},
                    {"name": "_changePKH", "type": "Addr"},
                    {"name": "_changeAmount", "type": "bigint"},
                ],
                "body": [
                    {"name": "t0", "value": {"kind": "load_prop", "name": "count"}},
                    {"name": "t1", "value": {"kind": "load_const", "value": 1}},
                    {"name": "t2", "value": {"kind": "bin_op", "op": "-", "left": "t0", "right": "t1"}},
                    {"name": "t3", "value": {"kind": "update_prop", "name": "count", "value": "t2"}},
                ],
                "isPublic": True,
            },
        ],
    }


def _branch_counter_anf() -> dict:
    """Counter that increments by 1 when count > 0, else increments by 2."""
    return {
        "contractName": "BranchCounter",
        "properties": [
            {"name": "count", "type": "bigint", "readonly": False},
        ],
        "methods": [
            {
                "name": "constructor",
                "params": [{"name": "count", "type": "bigint"}],
                "body": [],
                "isPublic": False,
            },
            {
                "name": "step",
                "params": [
                    {"name": "txPreimage", "type": "SigHashPreimage"},
                    {"name": "_changePKH", "type": "Addr"},
                    {"name": "_changeAmount", "type": "bigint"},
                ],
                "body": [
                    {"name": "t0", "value": {"kind": "load_prop", "name": "count"}},
                    {"name": "t1", "value": {"kind": "load_const", "value": 0}},
                    {"name": "t2", "value": {"kind": "bin_op", "op": ">", "left": "t0", "right": "t1"}},
                    {
                        "name": "t3",
                        "value": {
                            "kind": "if",
                            "cond": "t2",
                            "then": [
                                {"name": "ta0", "value": {"kind": "load_prop", "name": "count"}},
                                {"name": "ta1", "value": {"kind": "load_const", "value": 1}},
                                {"name": "ta2", "value": {"kind": "bin_op", "op": "+", "left": "ta0", "right": "ta1"}},
                                {"name": "ta3", "value": {"kind": "update_prop", "name": "count", "value": "ta2"}},
                            ],
                            "else": [
                                {"name": "tb0", "value": {"kind": "load_prop", "name": "count"}},
                                {"name": "tb1", "value": {"kind": "load_const", "value": 2}},
                                {"name": "tb2", "value": {"kind": "bin_op", "op": "+", "left": "tb0", "right": "tb1"}},
                                {"name": "tb3", "value": {"kind": "update_prop", "name": "count", "value": "tb2"}},
                            ],
                        },
                    },
                ],
                "isPublic": True,
            },
        ],
    }


# ---------------------------------------------------------------------------
# Basic counter tests (rows 457, 458)
# ---------------------------------------------------------------------------

class TestCounterIncrement:
    def test_increment_count_0_to_1(self):
        """Counter increment: count 0 → 1 (row 457)."""
        anf = _counter_anf()
        new_state = compute_new_state(anf, 'increment', {'count': 0}, {})
        assert new_state['count'] == 1

    def test_increment_count_5_to_6(self):
        """Counter increment: count 5 → 6."""
        anf = _counter_anf()
        new_state = compute_new_state(anf, 'increment', {'count': 5}, {})
        assert new_state['count'] == 6

    def test_decrement_count_5_to_4(self):
        """Counter decrement: count 5 → 4 (row 458)."""
        anf = _counter_anf()
        new_state = compute_new_state(anf, 'decrement', {'count': 5}, {})
        assert new_state['count'] == 4


# ---------------------------------------------------------------------------
# If/else branch selection (row 459)
# ---------------------------------------------------------------------------

class TestBranchSelection:
    def test_then_branch_when_count_positive(self):
        """count > 0 → then branch (+1) (row 459)."""
        anf = _branch_counter_anf()
        new_state = compute_new_state(anf, 'step', {'count': 3}, {})
        assert new_state['count'] == 4  # 3 + 1

    def test_else_branch_when_count_zero(self):
        """count == 0 → else branch (+2) (row 459)."""
        anf = _branch_counter_anf()
        new_state = compute_new_state(anf, 'step', {'count': 0}, {})
        assert new_state['count'] == 2  # 0 + 2


# ---------------------------------------------------------------------------
# Arithmetic operations (row 460)
# ---------------------------------------------------------------------------

class TestArithmeticOps:
    def _make_arith_anf(self, op: str) -> dict:
        return {
            "contractName": "Arith",
            "properties": [
                {"name": "result", "type": "bigint", "readonly": False},
            ],
            "methods": [
                {"name": "constructor", "params": [], "body": [], "isPublic": False},
                {
                    "name": "compute",
                    "params": [
                        {"name": "a", "type": "bigint"},
                        {"name": "b", "type": "bigint"},
                    ],
                    "body": [
                        {"name": "t0", "value": {"kind": "load_param", "name": "a"}},
                        {"name": "t1", "value": {"kind": "load_param", "name": "b"}},
                        {"name": "t2", "value": {"kind": "bin_op", "op": op, "left": "t0", "right": "t1"}},
                        {"name": "t3", "value": {"kind": "update_prop", "name": "result", "value": "t2"}},
                    ],
                    "isPublic": True,
                },
            ],
        }

    def test_addition(self):
        """add(3, 4) == 7 (row 460)."""
        anf = self._make_arith_anf('+')
        new_state = compute_new_state(anf, 'compute', {'result': 0}, {'a': 3, 'b': 4})
        assert new_state['result'] == 7

    def test_subtraction(self):
        """sub(10, 3) == 7 (row 460)."""
        anf = self._make_arith_anf('-')
        new_state = compute_new_state(anf, 'compute', {'result': 0}, {'a': 10, 'b': 3})
        assert new_state['result'] == 7

    def test_multiplication(self):
        """mul(5, 6) == 30 (row 460)."""
        anf = self._make_arith_anf('*')
        new_state = compute_new_state(anf, 'compute', {'result': 0}, {'a': 5, 'b': 6})
        assert new_state['result'] == 30


# ---------------------------------------------------------------------------
# @ref: aliases (row 461)
# ---------------------------------------------------------------------------

class TestRefAliases:
    def test_ref_alias_resolves_correctly(self):
        """load_const '@ref:t0' resolves to the value of t0 (row 461)."""
        anf = {
            "contractName": "RefTest",
            "properties": [
                {"name": "val", "type": "bigint", "readonly": False},
            ],
            "methods": [
                {"name": "constructor", "params": [], "body": [], "isPublic": False},
                {
                    "name": "copy",
                    "params": [{"name": "x", "type": "bigint"}],
                    "body": [
                        {"name": "t0", "value": {"kind": "load_param", "name": "x"}},
                        # @ref: alias — should resolve to t0's value
                        {"name": "t1", "value": {"kind": "load_const", "value": "@ref:t0"}},
                        {"name": "t2", "value": {"kind": "update_prop", "name": "val", "value": "t1"}},
                    ],
                    "isPublic": True,
                },
            ],
        }
        new_state = compute_new_state(anf, 'copy', {'val': 0}, {'x': 42})
        assert new_state['val'] == 42


# ---------------------------------------------------------------------------
# Error: unknown method (row 462)
# ---------------------------------------------------------------------------

class TestUnknownMethod:
    def test_unknown_method_raises_error(self):
        """compute_new_state with unknown method raises ValueError (row 462)."""
        anf = _counter_anf()
        with pytest.raises(ValueError, match='not found'):
            compute_new_state(anf, 'nonexistent', {'count': 0}, {})


# ---------------------------------------------------------------------------
# Implicit params not required (row 463)
# ---------------------------------------------------------------------------

class TestImplicitParams:
    def test_implicit_params_not_required_in_args(self):
        """txPreimage and _changePKH don't need to be in args dict (row 463)."""
        anf = _counter_anf()
        # Don't pass txPreimage, _changePKH, _changeAmount
        new_state = compute_new_state(anf, 'increment', {'count': 5}, {})
        assert new_state['count'] == 6


# ---------------------------------------------------------------------------
# hash builtins (row 465)
# ---------------------------------------------------------------------------

class TestHashBuiltins:
    def _make_hash_anf(self, func: str) -> dict:
        return {
            "contractName": "HashTest",
            "properties": [
                {"name": "digest", "type": "ByteString", "readonly": False},
            ],
            "methods": [
                {"name": "constructor", "params": [], "body": [], "isPublic": False},
                {
                    "name": "compute",
                    "params": [{"name": "data", "type": "ByteString"}],
                    "body": [
                        {"name": "t0", "value": {"kind": "load_param", "name": "data"}},
                        {"name": "t1", "value": {"kind": "call", "func": func, "args": ["t0"]}},
                        {"name": "t2", "value": {"kind": "update_prop", "name": "digest", "value": "t1"}},
                    ],
                    "isPublic": True,
                },
            ],
        }

    def test_hash160_produces_40_hex_chars(self):
        """hash160('') → 40 hex chars (20 bytes) (row 465)."""
        anf = self._make_hash_anf('hash160')
        new_state = compute_new_state(anf, 'compute', {'digest': ''}, {'data': ''})
        assert len(new_state['digest']) == 40  # 20 bytes

    def test_sha256_produces_64_hex_chars(self):
        """sha256('') → 64 hex chars (32 bytes) (row 465)."""
        anf = self._make_hash_anf('sha256')
        new_state = compute_new_state(anf, 'compute', {'digest': ''}, {'data': ''})
        assert len(new_state['digest']) == 64  # 32 bytes

    def test_hash256_produces_64_hex_chars(self):
        """hash256('') → 64 hex chars (row 465)."""
        anf = self._make_hash_anf('hash256')
        new_state = compute_new_state(anf, 'compute', {'digest': ''}, {'data': ''})
        assert len(new_state['digest']) == 64

    def test_ripemd160_produces_40_hex_chars(self):
        """ripemd160('') → 40 hex chars (row 465)."""
        anf = self._make_hash_anf('ripemd160')
        new_state = compute_new_state(anf, 'compute', {'digest': ''}, {'data': ''})
        assert len(new_state['digest']) == 40


# ---------------------------------------------------------------------------
# checkSig always returns true (row 467)
# ---------------------------------------------------------------------------

class TestCheckSigAlwaysTrue:
    def test_checksig_returns_true(self):
        """Mock checkSig in the ANF interpreter always returns True (row 467)."""
        anf = {
            "contractName": "SigTest",
            "properties": [
                {"name": "result", "type": "bool", "readonly": False},
            ],
            "methods": [
                {"name": "constructor", "params": [], "body": [], "isPublic": False},
                {
                    "name": "verify",
                    "params": [
                        {"name": "sig", "type": "Sig"},
                        {"name": "pubKey", "type": "PubKey"},
                    ],
                    "body": [
                        {"name": "t0", "value": {"kind": "load_param", "name": "sig"}},
                        {"name": "t1", "value": {"kind": "load_param", "name": "pubKey"}},
                        {"name": "t2", "value": {"kind": "call", "func": "checkSig", "args": ["t0", "t1"]}},
                        {"name": "t3", "value": {"kind": "update_prop", "name": "result", "value": "t2"}},
                    ],
                    "isPublic": True,
                },
            ],
        }
        sig_hex = '00' * 72
        pk_hex = '02' + 'ab' * 32
        new_state = compute_new_state(anf, 'verify', {'result': False}, {'sig': sig_hex, 'pubKey': pk_hex})
        assert new_state['result'] is True


# ---------------------------------------------------------------------------
# add_output state continuation (row 468)
# ---------------------------------------------------------------------------

class TestAddOutputStateTracking:
    def test_add_output_updates_mutable_props(self):
        """add_output binding updates mutable state fields (row 468)."""
        anf = {
            "contractName": "StatefulCounter",
            "properties": [
                {"name": "count", "type": "bigint", "readonly": False},
            ],
            "methods": [
                {"name": "constructor", "params": [], "body": [], "isPublic": False},
                {
                    "name": "increment",
                    "params": [
                        {"name": "txPreimage", "type": "SigHashPreimage"},
                        {"name": "_changePKH", "type": "Addr"},
                        {"name": "_changeAmount", "type": "bigint"},
                    ],
                    "body": [
                        {"name": "t0", "value": {"kind": "load_prop", "name": "count"}},
                        {"name": "t1", "value": {"kind": "load_const", "value": 1}},
                        {"name": "t2", "value": {"kind": "bin_op", "op": "+", "left": "t0", "right": "t1"}},
                        {
                            "name": "t3",
                            "value": {
                                "kind": "add_output",
                                "satoshis": "_newAmount",
                                "stateValues": ["t2"],
                            },
                        },
                    ],
                    "isPublic": True,
                },
            ],
        }
        new_state = compute_new_state(anf, 'increment', {'count': 0}, {})
        # count should be updated to 1
        assert new_state['count'] == 1


# ---------------------------------------------------------------------------
# NEW-006: a byte-op's RAW stack bytes must follow the value across an ALIAS
# ---------------------------------------------------------------------------
#
# The interpreter threads each numeric byte-array op's real stack bytes
# (& | ^ << >> ~) through a per-binding side map so a chained length-sensitive
# op sees the true, possibly NON-minimal width. That entry has to travel with
# the value across every binding that merely aliases another binding's stack
# slot -- the `load_const "@ref:<name>"` a local rebind lowers to, an `if`
# adopting its taken arm's last value, a `loop` adopting its body's -- because
# `05-stack-lower` carries its `rawSlots` marker across exactly those
# constructs. Ported from the TS fix (packages/runar-sdk/src/anf-interpreter.ts,
# `aliasScriptBytes`).

def _byte_op_anf(body: list) -> dict:
    """One-property contract wrapping a raw method body of byte ops."""
    return {
        "contractName": "ByteOps",
        "properties": [
            {"name": "result", "type": "bigint", "readonly": False},
        ],
        "methods": [
            {"name": "constructor", "params": [], "body": [], "isPublic": False},
            {"name": "compute", "params": [], "body": body, "isPublic": True},
        ],
    }


# `2 << 8` on a 1-byte operand shifts every bit out and leaves a NON-minimal
# 1-byte 0x00 on the stack -- the minimal encoding of 0 is the EMPTY push, so
# re-minimising this value loses a byte of width.
_SHIFT_TO_NONMINIMAL_ZERO = [
    {"name": "t0", "value": {"kind": "load_const", "value": 2}},
    {"name": "t1", "value": {"kind": "load_const", "value": 8}},
    {"name": "t2", "value": {"kind": "bin_op", "op": "<<", "left": "t0", "right": "t1"}},
]


class TestAliasCarriesScriptBytes:
    def test_ref_alias_propagates_raw_bytes(self):
        """`let m0 = 2n << 8n; m0 | 5n` == 5 -- the alias keeps the 1-byte width.

        Every local rebind lowers to `load_const "@ref:<temp>"`. Without the
        alias carry the map has no entry for `m0`, so OP_OR re-minimises 0 to
        the empty push and aborts on a 0-vs-1 byte length mismatch.
        """
        body = _SHIFT_TO_NONMINIMAL_ZERO + [
            {"name": "m0", "value": {"kind": "load_const", "value": "@ref:t2"}},
            {"name": "t3", "value": {"kind": "load_const", "value": 5}},
            {"name": "t4", "value": {"kind": "bin_op", "op": "|", "left": "m0", "right": "t3"}},
            {"name": "t5", "value": {"kind": "update_prop", "name": "result", "value": "t4"}},
        ]
        new_state = compute_new_state(_byte_op_anf(body), 'compute', {'result': 0}, {})
        assert new_state['result'] == 5

    def test_ref_alias_clears_stale_bytes_on_rebind(self):
        """`m0 = 2n << 8n; m0 = 300n; m0 & 255n` == 44 -- the alias CLEARS.

        HONESTY NOTE: this passes on the UNFIXED interpreter (nothing keys the
        map by a re-bound name yet). It is the guard that forces the clear half
        of the fix: a copy-only `aliasScriptBytes` would leave the dead 1-byte
        0x00 from the first binding of `m0` as the recorded width of a slot that
        now holds the 2-byte 0x2c01, and this test goes RED.
        """
        body = _SHIFT_TO_NONMINIMAL_ZERO + [
            {"name": "m0", "value": {"kind": "load_const", "value": "@ref:t2"}},
            # `m0 = 300n` -- the value is a fresh minimal push, so the slot's
            # recorded width must be dropped, not inherited.
            {"name": "t3", "value": {"kind": "load_const", "value": 300}},
            {"name": "m0", "value": {"kind": "load_const", "value": "@ref:t3"}},
            {"name": "t4", "value": {"kind": "load_const", "value": 255}},
            {"name": "t5", "value": {"kind": "bin_op", "op": "&", "left": "m0", "right": "t4"}},
            {"name": "t6", "value": {"kind": "update_prop", "name": "result", "value": "t5"}},
        ]
        new_state = compute_new_state(_byte_op_anf(body), 'compute', {'result': 0}, {})
        # 0x2c01 & 0xff00 == 0x2c00 == 44
        assert new_state['result'] == 44

    def test_ref_alias_clear_prevents_silently_wrong_value(self):
        """Same clear, in the shape where copy-only returns a WRONG value.

        The stale entry here is a 2-byte 0x0000 (`300n ^ 300n`), the same width
        as the value that replaces it, so a copy-only fix does not abort on a
        length mismatch -- it computes 0x0000 & 0xff00 == 0 and reports 0 as the
        state. Also passes unfixed, RED under copy-only.
        """
        body = [
            {"name": "t0", "value": {"kind": "load_const", "value": 300}},
            {"name": "t1", "value": {"kind": "load_const", "value": 300}},
            {"name": "t2", "value": {"kind": "bin_op", "op": "^", "left": "t0", "right": "t1"}},
            {"name": "m0", "value": {"kind": "load_const", "value": "@ref:t2"}},
            {"name": "t3", "value": {"kind": "load_const", "value": 300}},
            {"name": "m0", "value": {"kind": "load_const", "value": "@ref:t3"}},
            {"name": "t4", "value": {"kind": "load_const", "value": 255}},
            {"name": "t5", "value": {"kind": "bin_op", "op": "&", "left": "m0", "right": "t4"}},
            {"name": "t6", "value": {"kind": "update_prop", "name": "result", "value": "t5"}},
        ]
        new_state = compute_new_state(_byte_op_anf(body), 'compute', {'result': 0}, {})
        assert new_state['result'] == 44

    def test_if_result_propagates_taken_arm_raw_bytes(self):
        """An `if` adopts its taken arm's last value -- and that value's width."""
        body = [
            {"name": "c0", "value": {"kind": "load_const", "value": 1}},
            {
                "name": "t3",
                "value": {
                    "kind": "if",
                    "cond": "c0",
                    "then": [
                        {"name": "a0", "value": {"kind": "load_const", "value": 2}},
                        {"name": "a1", "value": {"kind": "load_const", "value": 8}},
                        {"name": "a2", "value": {"kind": "bin_op", "op": "<<", "left": "a0", "right": "a1"}},
                    ],
                    "else": [
                        {"name": "b0", "value": {"kind": "load_const", "value": 0}},
                    ],
                },
            },
            {"name": "t4", "value": {"kind": "load_const", "value": 5}},
            {"name": "t5", "value": {"kind": "bin_op", "op": "|", "left": "t3", "right": "t4"}},
            {"name": "t6", "value": {"kind": "update_prop", "name": "result", "value": "t5"}},
        ]
        new_state = compute_new_state(_byte_op_anf(body), 'compute', {'result': 0}, {})
        assert new_state['result'] == 5

    def test_loop_result_propagates_body_raw_bytes(self):
        """A `loop` adopts its body's last value -- and that value's width."""
        body = [
            {
                "name": "t0",
                "value": {
                    "kind": "loop",
                    "count": 1,
                    "iterVar": "i",
                    "body": [
                        {"name": "a0", "value": {"kind": "load_const", "value": 2}},
                        {"name": "a1", "value": {"kind": "load_const", "value": 8}},
                        {"name": "a2", "value": {"kind": "bin_op", "op": "<<", "left": "a0", "right": "a1"}},
                    ],
                },
            },
            {"name": "t1", "value": {"kind": "load_const", "value": 5}},
            {"name": "t2", "value": {"kind": "bin_op", "op": "|", "left": "t0", "right": "t1"}},
            {"name": "t3", "value": {"kind": "update_prop", "name": "result", "value": "t2"}},
        ]
        new_state = compute_new_state(_byte_op_anf(body), 'compute', {'result': 0}, {})
        assert new_state['result'] == 5


# ---------------------------------------------------------------------------
# NEW-013 -- `num2bin` sign-bit placement
# ---------------------------------------------------------------------------
#
# The ANF interpreter models what the DEPLOYED SCRIPT computes. For negative
# values it used to set the sign bit on the last MAGNITUDE byte and pad zeros
# AFTER it, so ``num2bin(-1, 2)`` came out ``8100`` where OP_NUM2BIN yields
# ``0180``. Those bytes go into the call transaction, so a legal method built a
# continuation the script rejects.
#
# Every expectation below is the output of OP_NUM2BIN on the real ``@bsv/sdk``
# Spend interpreter, derived by
# ``conformance/anf-interpreter/num2bin-engine-parity.test.ts``, which re-runs
# the engine live rather than trusting a table. Do NOT re-stamp these from this
# implementation's own output -- that is precisely how six of seven SDKs agreed
# on the wrong answer.

_NUM2BIN_ENGINE_VECTORS = [
    # (value, width, expected, why)
    # Negative, padded -- the NEW-013 corner. The sign bit belongs on the byte
    # that is most significant AFTER padding, not before it.
    (-1, 2, "0180", "negative padded"),
    (-1, 4, "01000080", "negative padded"),
    (-1, 8, "0100000000000080", "negative padded"),
    (-5, 4, "05000080", "negative padded"),
    (-1000, 4, "e8030080", "negative padded"),
    (-1000, 8, "e803000000000080", "negative padded"),
    (-255, 3, "ff0080", "negative padded"),
    (-256, 3, "000180", "negative padded"),
    # Negative, exact width -- the minimal encoding already fills the field, so
    # it is pushed unchanged and the sign bit does not move.
    (-1, 1, "81", "negative exact width"),
    (-127, 1, "ff", "negative exact width"),
    (-1000, 2, "e883", "negative exact width"),
    (-256, 2, "0081", "negative exact width"),
    # Negative, sign-bit carry -- the top magnitude byte already uses bit 7, so
    # the minimal encoding grows a byte before any padding happens.
    (-128, 2, "8080", "negative carry, exact width"),
    (-128, 3, "800080", "negative carry, padded"),
    (-128, 8, "8000000000000080", "negative carry, padded"),
    (-32768, 3, "008080", "negative carry, exact width"),
    (-32768, 4, "00800080", "negative carry, padded"),
    # Positive at the same widths -- must be untouched by the fix.
    (1, 1, "01", "positive exact width"),
    (1, 2, "0100", "positive padded"),
    (1, 8, "0100000000000000", "positive padded"),
    (1000, 2, "e803", "positive exact width"),
    (1000, 4, "e8030000", "positive padded"),
    (1000, 8, "e803000000000000", "positive padded"),
    (127, 1, "7f", "positive exact width"),
    (128, 2, "8000", "positive carry, exact width"),
    (128, 3, "800000", "positive carry, padded"),
    (255, 2, "ff00", "positive carry, exact width"),
    # Zero -- an all-zero field, no sign bit anywhere.
    (0, 1, "00", "zero"),
    (0, 4, "00000000", "zero"),
    (0, 8, "0000000000000000", "zero"),
]


@pytest.mark.parametrize("n,width,expected,why", _NUM2BIN_ENGINE_VECTORS)
def test_num2bin_hex_matches_op_num2bin(n, width, expected, why):
    from runar.sdk.anf_interpreter import _num2bin_hex

    assert _num2bin_hex(n, width) == expected, f"num2bin({n}, {width}) [{why}]"


def test_num2bin_hex_is_not_the_pre_fix_encoding():
    """Non-vacuity: the table only earns its keep if it can see the old answer.

    ``8100`` is exactly what ``_num2bin_hex(-1, 2)`` used to return.
    """
    from runar.sdk.anf_interpreter import _num2bin_hex

    assert _num2bin_hex(-1, 2) != "8100"


def test_num2bin_round_trip_is_smoke_test_only():
    """bin2num is this interpreter's own inverse, so a round trip proves only
    self-consistency -- it held throughout the bug. Kept as a smoke test; the
    vector table above is the evidence."""
    from runar.sdk.anf_interpreter import _bin2num_int, _num2bin_hex

    for n in (-1000, -128, -1, 0, 1, 128, 1000):
        assert _bin2num_int(_num2bin_hex(n, 8)) == n

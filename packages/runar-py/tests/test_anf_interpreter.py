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

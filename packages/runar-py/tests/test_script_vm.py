"""Tests for the Python ScriptVM wrapper (GAP-M2, Phase C).

``runar.sdk.script_vm`` wraps the optional ``bsv-sdk`` ``Spend`` interpreter.
``bsv-sdk`` is an optional dependency (``runar-py`` itself is zero-dependency),
so these tests ``importorskip`` it: they run when the ``script-vm`` extra is
installed and skip cleanly otherwise — EXCEPT in CI, where a missing
``bsv-sdk`` is treated as a hard failure (T-8 from
audits/cross-language-completeness-20260514.md §5.2).
"""

from __future__ import annotations

import importlib.util
import os

import pytest

# T-8: in CI we want a missing ``bsv-sdk`` to be loud, not a silent skip.
# The Python SDK CI job (``.github/workflows/ci.yml`` → ``python-sdk`` →
# ``pip install pytest slh-dsa bsv-sdk``) explicitly installs the
# ``script-vm`` extra so test_script_vm.py runs its real path. If a future
# CI change drops the install (or installs a broken bsv-sdk) the silent
# importorskip below would let ScriptVM regressions ship uncaught; this
# gate flips that into a hard, visible failure.
if os.environ.get("CI") and importlib.util.find_spec("bsv") is None:
    pytest.fail(
        "test_script_vm.py: CI environment detected ($CI is set) but the "
        "optional `bsv-sdk` package is not installed — the ScriptVM tests "
        "would silently skip. Install the `script-vm` extra in CI "
        "(`pip install runar[script-vm]` or `pip install bsv-sdk`). See "
        "audits/cross-language-completeness-20260514.md T-8.",
        pytrace=False,
    )

# Skip the whole module unless the optional bsv-sdk dependency is available.
pytest.importorskip("bsv", reason="bsv-sdk not installed (runar[script-vm] extra)")

from runar.sdk.script_vm import ScriptVM, VMResult, StepResult  # noqa: E402


# ---------------------------------------------------------------------------
# One-shot execution
# ---------------------------------------------------------------------------


def test_execute_hex_arithmetic_succeeds() -> None:
    # OP_2 OP_3 OP_ADD OP_5 OP_EQUAL (5253935587): 2 + 3 == 5.
    vm = ScriptVM()
    res = vm.execute_hex("5253935587")
    assert isinstance(res, VMResult)
    assert res.success, f"expected success, error: {res.error}"
    assert res.stack == [b"\x01"]
    assert res.ops_executed == 5
    assert res.error is None


def test_execute_hex_false_comparison_fails() -> None:
    # OP_2 OP_3 OP_EQUAL (525387): 2 == 3 is false.
    vm = ScriptVM()
    res = vm.execute_hex("525387")
    assert not res.success
    assert res.error is not None


def test_execute_unlocking_and_locking() -> None:
    # unlocking: OP_5 (0x55), locking: OP_5 OP_EQUAL (0x55 0x87).
    vm = ScriptVM()
    res = vm.execute(b"\x55", b"\x55\x87")
    assert res.success, f"expected success, error: {res.error}"


def test_execute_malformed_script_reports_error() -> None:
    # Unbalanced OP_ENDIF (0x68) is a hard interpreter error.
    vm = ScriptVM()
    res = vm.execute(b"", b"\x68")
    assert not res.success
    assert res.error is not None


# ---------------------------------------------------------------------------
# Step mode (debugger API)
# ---------------------------------------------------------------------------


def test_step_mode_walks_each_opcode_in_order() -> None:
    vm = ScriptVM()
    vm.load_hex("", "5253935587")

    want_opcodes = ["OP_2", "OP_3", "OP_ADD", "OP_5", "OP_EQUAL"]
    want_depth = [1, 2, 1, 2, 1]  # main-stack depth after each opcode

    seen: list[str] = []
    i = 0
    while (step := vm.step()) is not None:
        assert isinstance(step, StepResult)
        assert step.opcode == want_opcodes[i], f"step {i}: {step.opcode}"
        assert len(step.main_stack) == want_depth[i], f"step {i}: depth"
        assert step.context == "locking"
        seen.append(step.opcode)
        i += 1

    assert seen == want_opcodes
    assert vm.is_complete
    assert vm.is_success
    assert vm.pc == 5


def test_step_mode_reports_context_transition() -> None:
    vm = ScriptVM()
    # unlocking: OP_5 (55), locking: OP_5 OP_EQUAL (5587).
    vm.load_hex("55", "5587")

    s1 = vm.step()
    assert s1 is not None and s1.context == "unlocking"
    s2 = vm.step()
    assert s2 is not None and s2.context == "locking"
    s3 = vm.step()
    assert s3 is not None and s3.context == "locking"
    assert vm.step() is None


def test_step_returns_none_when_nothing_loaded() -> None:
    vm = ScriptVM()
    assert vm.step() is None
    assert not vm.is_complete


# ---------------------------------------------------------------------------
# Cross-tier signature vector (N-098 / F-124)
# ---------------------------------------------------------------------------

# A P2PKH spend signed against the TS ScriptVM's synthetic spend context
# (version 1, 100000 sats, null outpoint, sequence 0xffffffff, locktime 0;
# key 1, SIGHASH_ALL|FORKID). The signature only verifies if this VM's
# synthetic transaction carries the same source satoshis (part of the BIP-143
# preimage). Proves the Python VM agrees with TS and Go on that context; it
# does not independently pin the other preimage fields.
TS_P2PKH_LOCKING = "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac"
TS_P2PKH_UNLOCKING = (
    "4730440220459bb2da0b81e7a5b8aba3116a4ef6e2df9695b3d795af3ae30b5a928c1443ca0220"
    "44a077326ac6221fb76ee4629bd014d65357786e3577601846db5188721bf3db41210279be667e"
    "f9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
)


def test_ts_signed_p2pkh_spend_succeeds() -> None:
    res = ScriptVM().execute(bytes.fromhex(TS_P2PKH_UNLOCKING), bytes.fromhex(TS_P2PKH_LOCKING))
    assert res.success, f"TS-signed P2PKH spend must verify, error: {res.error}"


def test_corrupted_signature_p2pkh_spend_fails_at_checksig() -> None:
    unlocking = bytearray(bytes.fromhex(TS_P2PKH_UNLOCKING))
    unlocking[70] ^= 0x01  # last S byte, well-formed DER, wrong signature
    res = ScriptVM().execute(bytes(unlocking), bytes.fromhex(TS_P2PKH_LOCKING))
    assert not res.success
    assert res.error is not None and "OP_CHECKSIG" in res.error

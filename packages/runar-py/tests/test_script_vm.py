"""Tests for the Python ScriptVM wrapper (GAP-M2, Phase C).

``runar.sdk.script_vm`` wraps the optional ``bsv-sdk`` ``Spend`` interpreter.
``bsv-sdk`` is an optional dependency (``runar-py`` itself is zero-dependency),
so these tests ``importorskip`` it: they run when the ``script-vm`` extra is
installed and skip cleanly otherwise.
"""

from __future__ import annotations

import pytest

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

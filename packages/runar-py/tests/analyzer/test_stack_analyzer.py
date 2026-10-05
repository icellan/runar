"""Unit tests for stack analyzer (spec §8)."""

from __future__ import annotations

import pytest

from runar.analyzer import analyze_script
from runar.analyzer.script_parser import parse_script
from runar.analyzer.stack_analyzer import analyze_stack_linear, stack_effect


def test_stack_underflow_only_when_initial_depth_positive():
    # OP_DUP requires 1 item. With initial_depth=0, no underflow finding
    # is emitted (locking-script convention; the unlocking input is the
    # implicit source). With initial_depth>0, depth<pops triggers it.
    ops = parse_script("76")  # OP_DUP

    # initial_depth=0: no underflow finding.
    r0 = analyze_stack_linear(ops, initial_depth=0)
    assert not any(f.code == "STACK_UNDERFLOW" for f in r0.findings)

    # initial_depth=1: depth(1) >= pops(1), still no underflow.
    r1 = analyze_stack_linear(ops, initial_depth=1)
    assert not any(f.code == "STACK_UNDERFLOW" for f in r1.findings)

    # initial_depth=1 with OP_2DROP (pops=2): underflow.
    ops2 = parse_script("6d")
    r2 = analyze_stack_linear(ops2, initial_depth=1)
    assert any(f.code == "STACK_UNDERFLOW" for f in r2.findings)


def test_unreachable_after_return():
    # OP_RETURN OP_DUP — DUP is after RETURN.
    ops = parse_script("6a76")
    r = analyze_stack_linear(ops, initial_depth=0)
    codes = [f.code for f in r.findings]
    assert "UNREACHABLE_AFTER_RETURN" in codes


def test_final_depth_and_max_depth_track_correctly():
    # OP_1 OP_1 OP_1 OP_DROP → depths 1,2,3,2 ; max=3 ; final=2
    ops = parse_script("51515175")
    r = analyze_stack_linear(ops, initial_depth=0)
    assert r.final_depth == 2
    assert r.max_depth == 3


def test_negative_final_depth_allowed():
    # OP_DROP with initial depth 0 → final depth -1, no underflow finding.
    ops = parse_script("75")
    r = analyze_stack_linear(ops, initial_depth=0)
    assert r.final_depth == -1
    assert not r.findings


# The seven Chronicle opcodes the compiler emits, with the (pops, pushes)
# the @bsv/sdk interpreter (Spend.ts) gives them.
_CHRONICLE = [
    ("8d", "OP_2MUL", 1, 1),
    ("8e", "OP_2DIV", 1, 1),
    ("b3", "OP_SUBSTR", 3, 1),
    ("b4", "OP_LEFT", 2, 1),
    ("b5", "OP_RIGHT", 2, 1),
    ("b6", "OP_LSHIFTNUM", 2, 1),
    ("b7", "OP_RSHIFTNUM", 2, 1),
]


@pytest.mark.parametrize("byte,name,pops,pushes", _CHRONICLE)
def test_chronicle_opcode_name_and_effect(byte, name, pops, pushes):
    # F-131. Proves: the Chronicle opcode is named per spec §4.1 and modelled
    # with its real stack effect, in the lookup and in the observable report
    # (underflow message, stackDepthAtEnd, maxStackDepth). Does not prove
    # runtime semantics (the analyzer is static) and does not re-derive the
    # arities from the interpreter.
    (op,) = parse_script(byte)
    assert op.name == name
    assert stack_effect(op) == (pops, pushes)

    # OP_DROP empties a stack of known depth 1, then the opcode needs `pops` items.
    lin = analyze_stack_linear(parse_script("75" + byte), initial_depth=1)
    want = f"{name} requires {pops} stack item(s) but only 0 available"
    assert any(f.code == "STACK_UNDERFLOW" and f.message == want for f in lin.findings)

    # `pops` pushes of OP_1 then the opcode leave exactly `pushes` items.
    r = analyze_script("51" * pops + byte)
    assert r.paths[0].stack_depth_at_end == pushes
    assert r.summary.max_stack_depth == pushes


def test_genuinely_unknown_byte_keeps_unknown_name_and_zero_effect():
    (op,) = parse_script("b8")
    assert op.name == "OP_UNKNOWN(0xb8)"
    assert stack_effect(op) == (0, 0)

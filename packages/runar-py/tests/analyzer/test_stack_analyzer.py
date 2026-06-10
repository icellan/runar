"""Unit tests for stack analyzer (spec §8)."""

from __future__ import annotations

from runar.analyzer.script_parser import parse_script
from runar.analyzer.stack_analyzer import analyze_stack_linear


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

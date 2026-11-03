"""F-259 -- an unrolled loop body's opcodes map to the body statement's line,
not to the ``for`` line.

Before the fix ``_lower_loop`` lowered every body binding without updating
``current_source_loc``, so every opcode of every unrolled iteration inherited
the enclosing loop binding's location (the ``for`` line). Mirrors
packages/runar-compiler/src/__tests__/f259-loop-body-source-loc.test.ts.

Convention (same in all 7 tiers): each body binding's own location is used
while it lowers; a body binding without one keeps the loop's location. The
per-iteration iteration-variable push stays on the ``for`` line.

What this proves: end to end on the Python surface of
examples/python/bounded-loop, every body op of all five unrolled iterations
maps to the body line and column, and only the five iteration-variable pushes
(OP_0..OP_4) map to the ``for`` line.

What this does not prove: anything about the other tiers, nested loops, or
body bindings the ANF lowerer leaves without a location. It equates ASM token
index with opcodeIndex, which holds for this contract (no raw spans).
"""

from __future__ import annotations

from pathlib import Path

from runar_compiler.compiler import compile_from_source

SOURCE = (
    Path(__file__).resolve().parents[3]
    / "examples" / "python" / "bounded-loop" / "BoundedLoop.runar.py"
)


def test_loop_body_ops_map_to_the_body_line():
    src = SOURCE.read_text()
    artifact = compile_from_source(str(SOURCE), disable_constant_folding=True)

    lines = src.split("\n")

    def find(needle, anchor):
        for i, line in enumerate(lines):
            if needle in line:
                return i + 1, line.index(anchor)
        raise AssertionError(f"needle {needle!r} not in source")

    for_line, for_col = find("for i in range", "for")
    body_line, body_col = find("sum_ = sum_ + start + i", "sum_")

    asm = artifact.asm.split()
    iter_pushes = {1: "OP_0", 9: "OP_1", 17: "OP_2", 25: "OP_3", 33: "OP_4"}
    assert {i: asm[i] for i in iter_pushes} == iter_pushes, artifact.asm

    loop_ops = [
        (m.opcode_index, m.line, m.column)
        for m in artifact.source_map or []
        if 1 <= m.opcode_index <= 39
    ]
    assert len(loop_ops) == 39

    for idx, line, col in loop_ops:
        want = (for_line, for_col) if idx in iter_pushes else (body_line, body_col)
        assert (idx, line, col) == (idx, *want), f"opcode {idx} ({asm[idx]})"

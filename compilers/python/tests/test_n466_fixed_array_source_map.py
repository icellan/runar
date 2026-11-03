"""N-466 -- the Python tier mapped 284 opcodes of the TicTacToe v2 example to
0:0 where the TypeScript reference maps them to a real statement.

``lower_statements`` rewrites ``if (c) { ...; return x; } rest...`` into an
``if`` whose else-branch holds ``rest``. The rewritten ``IfStmt`` was built
without the original statement's ``source_location``, so the ``if`` binding
(and everything lowered under it) lost its location. The TypeScript pass
spreads the original statement (``{ ...stmt, else: remaining }``) and keeps it.

The reference is the TypeScript tier, pinned in n466_ts_reference_map.json as
runs [firstOpcode, lastOpcode, line, column]. Regenerate with
``runar compile examples/ts/tic-tac-toe/TicTacToe.v2.runar.ts -o <dir>
--disable-constant-folding --emit-source-map <out.json>``.

What this proves: compiling the same .runar.ts source with constant folding
off, the Python source map maps exactly the opcodes TS maps, each to the same
line and column.

What this does not prove: anything about other contracts, other tiers, or
fold-ON maps (the TS map is pinned, not recomputed). The 90-example sweep in
remediation-logs/N-394 covers the other examples.
"""

from __future__ import annotations

import json
from pathlib import Path

from runar_compiler.compiler import compile_from_source

SOURCE = (
    Path(__file__).resolve().parents[3]
    / "examples" / "ts" / "tic-tac-toe" / "TicTacToe.v2.runar.ts"
)
REFERENCE = Path(__file__).resolve().parent / "n466_ts_reference_map.json"


def _ts_reference() -> dict[int, tuple[int, int]]:
    runs = json.loads(REFERENCE.read_text())["tic-tac-toe-v2"]
    return {
        op: (line, col)
        for first, last, line, col in runs
        for op in range(first, last + 1)
    }


def test_early_return_if_keeps_its_source_location_like_ts():
    artifact = compile_from_source(str(SOURCE), disable_constant_folding=True)
    got = {m.opcode_index: (m.line, m.column) for m in artifact.source_map or []}
    want = _ts_reference()
    diffs = [
        f"#{i}: TS {want.get(i)} / Python {got.get(i)}"
        for i in sorted(set(want) | set(got))
        if want.get(i) != got.get(i)
    ]
    assert not diffs, f"{len(diffs)} opcodes differ from the TS map: {diffs[:10]}"

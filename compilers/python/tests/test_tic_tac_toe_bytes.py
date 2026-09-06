"""Cross-compiler byte-count locks for TicTacToe.

These tests lock in the fix for the missing ``liftBranchUpdateProps`` pass in
the Python ANF lowering stage, which caused the Python compiler to diverge
from TS/Go/Rust on contracts with position-dispatch patterns (nested
``if (pos == 0) { this.c0 = ... } else if (pos == 1) { this.c1 = ... }``).

All 6 Rúnar compilers must produce byte-identical Bitcoin Script for the
same canonical TypeScript source. For the canonical TicTacToe contracts
(both v1 hand-rolled and v2 FixedArray), the expected locking script size
is **9616 bytes** (19232 hex chars). The count grew 122 bytes from 9494 with
NEW-014 (``&&`` / ``||`` now SHORT-CIRCUIT on-chain). ``checkWinAfterMove``
is eight ``v_a == player && v_b == player && v_c == player`` chains, and
``&&`` is left-associative, so each one stops being a pair of OP_BOOLANDs and
becomes nested OP_IF / OP_ELSE branching. That growth is the FIX, not a
regression: OP_BOOLAND is a binary stack op, so both operands had to be
evaluated, and an operand the source meant to skip can abort the script
(``OP_DIV`` by zero, out-of-range ``OP_SPLIT``, undersized ``OP_NUM2BIN``).
The new bytes were EXECUTED before this number was changed, not merely agreed
on by seven tiers — see
``audits/v1-review/claude/repro/NEW-014-tictactoe-spends-at-9616.mts``, which
deploys and plays a full game on the real @bsv/sdk ``Spend`` engine: a winning
line pays out, and ``moveAndWin`` on a board with no line is REJECTED with
"OP_VERIFY requires the top stack value to be truthy" (the authorization case
— had the chains miscompiled to always-true, either player could steal the
pot). Before that it was 9494; the count grew 18 bytes to 9494
with the C17 fix (peephole ``not-not-elim`` guard): the rule was an unguarded
2-op window that composed with ``PUSH 0; OP_NUMEQUAL -> OP_NOT`` to delete
``x !== 0n`` outright, so TicTacToe's 9 × ``if (this.cN != 0n)`` comparisons
each regain their ``OP_NOT OP_NOT`` pair (first divergence at byte offset 5996).
Before that it was 9476: the count grew 27 bytes to 9476
with the C20 fix (anf-lower ``liftBranchUpdateProps``): TicTacToe's position
dispatch ends in ``assert(false)`` for out-of-range moves, and C20 re-emits that
dropped abort as ``assert(cond0 || ... || cond8)`` per method — restoring the
funds-safety guard, byte-identical to the TS/Go/Rust reference. Before that it
was 9449 bytes: the byte count grew to 9449 with the
#116 change-output gate: each change-emitting public method now carries an
additional 24 bytes (up from 9425 under the GAP-302 stateful-covenant
hardening, where each public method carries a fixed 760-byte, sighash-pinned
checkPreimage blob with OP_CHECKSIG inside the blob). (Historically the size
was 5087 bytes, up from 4951
when the state-continuation varint emitter learned all four Bitcoin
varint shapes (1/3/5/9 byte) — see integration/go/contracts/RollupBug.runar.go.)
"""

from __future__ import annotations

from pathlib import Path

from conftest import must_compile_source


# The canonical TicTacToe sources live in the top-level examples/ts/ tree
# because all compilers share the same canonical TypeScript inputs.
REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
TS_V1 = REPO_ROOT / "examples" / "ts" / "tic-tac-toe" / "TicTacToe.runar.ts"
TS_V2 = REPO_ROOT / "examples" / "ts" / "tic-tac-toe" / "TicTacToe.v2.runar.ts"
PY_DSL = REPO_ROOT / "examples" / "python" / "tic-tac-toe" / "TicTacToe.runar.py"

EXPECTED_BYTES = 9616


def _byte_len(hex_str: str) -> int:
    return len(hex_str) // 2


class TestTicTacToeCrossCompilerBytes:
    def test_canonical_ts_v1_locks_to_9616_bytes(self):
        assert TS_V1.exists(), f"missing canonical source: {TS_V1}"
        artifact = must_compile_source(str(TS_V1))
        assert _byte_len(artifact.script) == EXPECTED_BYTES, (
            f"canonical TS v1 TicTacToe must compile to {EXPECTED_BYTES} bytes "
            f"to match the TS/Go/Rust reference; got {_byte_len(artifact.script)}."
        )

    def test_canonical_ts_v2_locks_to_9616_bytes(self):
        assert TS_V2.exists(), f"missing canonical source: {TS_V2}"
        artifact = must_compile_source(str(TS_V2))
        assert _byte_len(artifact.script) == EXPECTED_BYTES, (
            f"canonical TS v2 (FixedArray) TicTacToe must compile to "
            f"{EXPECTED_BYTES} bytes; got {_byte_len(artifact.script)}."
        )

    def test_v1_and_v2_produce_byte_identical_output(self):
        assert TS_V1.exists() and TS_V2.exists()
        a1 = must_compile_source(str(TS_V1))
        a2 = must_compile_source(str(TS_V2))
        assert a1.script == a2.script, (
            "TicTacToe v1 (hand-rolled 9 scalar fields) and v2 "
            "(FixedArray<bigint, 9>) must desugar to byte-identical "
            "Bitcoin Script."
        )

    def test_python_dsl_source_locks_to_9616_bytes(self):
        # The Python DSL TicTacToe is a snake_case port of the TS source.
        # It was reported as 4684 bytes before the liftBranchUpdateProps
        # port, confirming the same bug affected Python-DSL parsing as well.
        assert PY_DSL.exists(), f"missing Python DSL source: {PY_DSL}"
        artifact = must_compile_source(str(PY_DSL))
        assert _byte_len(artifact.script) == EXPECTED_BYTES, (
            f"Python DSL TicTacToe must compile to {EXPECTED_BYTES} bytes "
            f"(same as the canonical TS source); got "
            f"{_byte_len(artifact.script)}."
        )

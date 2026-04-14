"""Cross-compiler byte-count locks for TicTacToe.

These tests lock in the fix for the missing ``liftBranchUpdateProps`` pass in
the Python ANF lowering stage, which caused the Python compiler to diverge
from TS/Go/Rust on contracts with position-dispatch patterns (nested
``if (pos == 0) { this.c0 = ... } else if (pos == 1) { this.c1 = ... }``).

All 6 Rúnar compilers must produce byte-identical Bitcoin Script for the
same canonical TypeScript source. For the canonical TicTacToe contracts
(both v1 hand-rolled and v2 FixedArray), the expected locking script size
is **5027 bytes** (10054 hex chars). The byte count went from 4951 to
5027 when the state-continuation varint emitter was extended to handle
all four Bitcoin varint shapes (1/3/5/9 byte) — see the varint fix in
integration/go/contracts/RollupBug.runar.go.
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

EXPECTED_BYTES = 5027


def _byte_len(hex_str: str) -> int:
    return len(hex_str) // 2


class TestTicTacToeCrossCompilerBytes:
    def test_canonical_ts_v1_locks_to_5027_bytes(self):
        assert TS_V1.exists(), f"missing canonical source: {TS_V1}"
        artifact = must_compile_source(str(TS_V1))
        assert _byte_len(artifact.script) == EXPECTED_BYTES, (
            f"canonical TS v1 TicTacToe must compile to {EXPECTED_BYTES} bytes "
            f"to match the TS/Go/Rust reference; got {_byte_len(artifact.script)}."
        )

    def test_canonical_ts_v2_locks_to_5027_bytes(self):
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

    def test_python_dsl_source_locks_to_5027_bytes(self):
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

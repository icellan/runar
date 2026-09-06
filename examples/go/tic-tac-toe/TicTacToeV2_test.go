package contract

import (
	"testing"

	"github.com/icellan/runar/compilers/go/compiler"
	runar "github.com/icellan/runar/packages/runar-go"
)

// Compile-check for the v2 contract: runs the full Go compiler pipeline
// through parse → validate → typecheck → expand → ANF → stack → emit and
// verifies that the result is a valid non-empty Rúnar artifact.
func TestTicTacToeV2_Compile(t *testing.T) {
	if err := runar.CompileCheck("TicTacToe.v2.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}

// TestTicTacToeV2_ByteIdenticalToV1 is the acceptance test for the
// FixedArray feature in the Go compiler. It compiles both the
// hand-rolled v1 contract and the v2 FixedArray rewrite through the full
// Go compiler pipeline and asserts that the resulting locking scripts
// are byte-identical and have length 9616. (BUG-100: each of the three public
// methods now carries the fixed on-chain OP_PUSH_TX preimage-binding blob, so
// the script grew from the pre-fix 5087 bytes. #116: the numeric `!=` migration
// to [OP_NUMEQUAL, OP_NOT] added one byte per numeric inequality, growing the
// script from 9425 to 9449. Deep-review C20: makeMove's 9-way position dispatch
// ends in assert(false); the anf-lower fix (liftBranchUpdateProps) re-emits that
// dropped abort as assert(cond0 || ... || cond8), growing the script from 9449
// to 9476. Deep-review C17: `not-not-elim` was an unguarded 2-op rule that
// composed with `PUSH 0; OP_NUMEQUAL -> OP_NOT` to delete `x !== 0n` outright;
// the guarded 3-op rule lets the 9 × `if (this.cN != 0n)` comparisons regain
// their OP_NOT OP_NOT pair, growing the script from 9476 to 9494 — verified
// byte-identical against the fixed TS reference. NEW-014: `&&` / `||` now
// SHORT-CIRCUIT on-chain — checkWinAfterMove is eight
// `v_a == player && v_b == player && v_c == player` chains and `&&` is
// left-associative, so each stops being a pair of OP_BOOLANDs and becomes
// nested OP_IF / OP_ELSE branching, growing the script from 9494 to 9616. The
// growth IS the fix: OP_BOOLAND is a binary stack op, so both operands had to
// be evaluated, and an operand the source meant to skip can abort the script.
// These bytes were EXECUTED before this number moved, not merely agreed on by
// seven tiers — audits/v1-review/claude/repro/NEW-014-tictactoe-spends-at-9616.mts
// plays a full game on the real @bsv/sdk Spend engine and proves that
// moveAndWin on a board with NO line is still REJECTED.)
//
// The v2 contract uses `Board [9]runar.Bigint`. The expand-fixed-arrays
// pass runs between typecheck and ANF lowering, expanding the array
// property into 9 scalar siblings `board__0..board__8` and rewriting all
// literal-index accesses into direct property accesses. The ANF / stack
// / emit passes see a contract with identical property count and
// declaration order to v1, so the compiled script must match bit-for-bit.
func TestTicTacToeV2_ByteIdenticalToV1(t *testing.T) {
	v1, err := compiler.CompileFromSource("TicTacToe.runar.go")
	if err != nil {
		t.Fatalf("v1 compile failed: %v", err)
	}
	v2, err := compiler.CompileFromSource("TicTacToe.v2.runar.go")
	if err != nil {
		t.Fatalf("v2 compile failed: %v", err)
	}

	if v1.Script == "" || v2.Script == "" {
		t.Fatalf("got empty scripts: v1=%d v2=%d", len(v1.Script), len(v2.Script))
	}

	// Locking script lengths are stored as hex, so byte count = hex/2.
	v1Bytes := len(v1.Script) / 2
	v2Bytes := len(v2.Script) / 2

	const expectedBytes = 9616
	if v1Bytes != expectedBytes {
		t.Errorf("v1 script length = %d bytes, want %d", v1Bytes, expectedBytes)
	}
	if v2Bytes != expectedBytes {
		t.Errorf("v2 script length = %d bytes, want %d", v2Bytes, expectedBytes)
	}

	if v1.Script != v2.Script {
		// Print a short prefix diff so failures surface where divergence begins.
		minLen := len(v1.Script)
		if len(v2.Script) < minLen {
			minLen = len(v2.Script)
		}
		diffAt := -1
		for i := 0; i < minLen; i++ {
			if v1.Script[i] != v2.Script[i] {
				diffAt = i
				break
			}
		}
		t.Fatalf("v1 and v2 scripts differ: lengths %d vs %d, first diff at hex offset %d",
			len(v1.Script), len(v2.Script), diffAt)
	}
}

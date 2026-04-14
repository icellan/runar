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
// are byte-identical and have length 5027.
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

	const expectedBytes = 5027
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

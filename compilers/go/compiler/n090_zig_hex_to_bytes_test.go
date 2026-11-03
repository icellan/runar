package compiler

import (
	"path/filepath"
	"testing"
)

// N-090: the checked-in examples/zig/tic-tac-toe/TicTacToe.runar.zig declares
// `p2pkhPrefix = runar.hexToBytes("1976a914")`. The Go tier refused it
// ("initializer must be a literal value") because its Zig parser left the call
// unlowered.
//
// Proves: the Zig-surface TicTacToe compiles in the Go tier and produces the
// same locking script as the TS-surface TicTacToe compiled by the same tier,
// so the hexToBytes initializers lower to the same bytes as the TS
// `"1976a914" as ByteString` initializers.
// Does NOT prove: identity with the TS compiler (pinned by the
// hex-to-bytes-initializer conformance fixture and the remediation sweep).
func TestN090_ZigTicTacToeHexToBytesCompiles(t *testing.T) {
	examples := filepath.Join(conformanceDir(), "..", "..", "examples")
	zigArt, err := CompileFromSource(filepath.Join(examples, "zig", "tic-tac-toe", "TicTacToe.runar.zig"))
	if err != nil {
		t.Fatalf("TicTacToe.runar.zig failed to compile: %v", err)
	}
	tsArt, err := CompileFromSource(filepath.Join(examples, "ts", "tic-tac-toe", "TicTacToe.runar.ts"))
	if err != nil {
		t.Fatalf("TicTacToe.runar.ts failed to compile: %v", err)
	}
	if zigArt.Script == "" || zigArt.Script != tsArt.Script {
		t.Fatalf("Zig-surface script differs from TS-surface script (zig %d hex chars, ts %d)", len(zigArt.Script), len(tsArt.Script))
	}
}

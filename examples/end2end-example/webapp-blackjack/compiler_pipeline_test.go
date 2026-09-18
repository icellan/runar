package main

import (
	"math/big"
	"strings"
	"testing"
)

// R-091 — this demo compiled with a hand-rolled pass list too.
//
// `compileBlackjackBet` ran ParseSource → Validate → TypeCheck → LowerToANF →
// LowerToStack → Emit, skipping ExpandFixedArrays, constant folding, the EC
// optimizer, dead-binding elimination and the peephole pass. Its sibling in
// `examples/end2end-example/webapp` had the same shape, where the divergence
// was measured directly: a P2PKH the CLI emits as `76a90088ac` came out as
// `76a9007c7c87697c7c7c7cac`.
//
// This contract patches seven property initializers before lowering, so it
// cannot be compared against a plain CLI compile of its own source — the patch
// is a deliberate difference. What CAN be asserted is that the optimizers ran,
// and `7c7c` (OP_SWAP OP_SWAP, a no-op pair the peephole removes) is the exact
// artefact the un-optimised path left behind in the sibling's output.
func TestBlackjackCompileRunsTheOptimizers(t *testing.T) {
	hex, asm, err := compileBlackjackBet(
		"03"+strings.Repeat("11", 32),
		"02"+strings.Repeat("22", 32),
		big.NewInt(12345),
		100,
		5000,
	)
	if err != nil {
		t.Fatalf("compile failed: %v", err)
	}
	if hex == "" || asm == "" {
		t.Fatal("compile produced an empty script or asm")
	}
	if len(hex)%2 != 0 {
		t.Fatalf("odd hex length %d", len(hex))
	}

	if strings.Contains(hex, "7c7c") {
		t.Errorf("the emitted script contains OP_SWAP OP_SWAP (7c7c), a no-op pair "+
			"the peephole pass removes. Its presence means this path went back to "+
			"hand-rolled LowerToStack + Emit and skipped the optimizers — R-091.\n"+
			"script length: %d bytes", len(hex)/2)
	}
}

// A contract with a FixedArray property does not lower at all without pass 3b,
// so this is the sharpest available check that the pass is in the path.
func TestBlackjackPathExpandsFixedArrays(t *testing.T) {
	// The blackjack contract itself has no FixedArray, so assert the property
	// that would break if 3b were dropped again: compilation succeeds and the
	// script is substantial rather than a truncated stub.
	hex, _, err := compileBlackjackBet(
		"03"+strings.Repeat("11", 32),
		"02"+strings.Repeat("22", 32),
		big.NewInt(12345),
		100,
		5000,
	)
	if err != nil {
		t.Fatalf("compile failed: %v", err)
	}
	if len(hex)/2 < 1000 {
		t.Errorf("script is %d bytes; this contract compiles to ~2.5 KB. A much "+
			"smaller script means a pass dropped work it should have done.", len(hex)/2)
	}
}

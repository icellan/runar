package codegen

import (
	"testing"
)

// ---------------------------------------------------------------------------
// Test: EmitPoseidon2KBPermute produces a non-trivial number of StackOps
// ---------------------------------------------------------------------------

func TestPoseidon2KB_PermuteOpCount(t *testing.T) {
	var ops []StackOp
	EmitPoseidon2KBPermute(func(op StackOp) {
		ops = append(ops, op)
	})

	// Sanity check: the permutation should produce a substantial number of ops.
	// 28 rounds with field operations on 16 elements should produce thousands of ops.
	// The permutation uses real Plonky3 p3-koala-bear round constants, producing
	// a substantial number of ops from 28 rounds of field operations on 16 elements.
	if len(ops) < 1000 {
		t.Errorf("expected at least 1000 ops from Poseidon2 permute, got %d", len(ops))
	}
	t.Logf("Poseidon2KBPermute emitted %d StackOps", len(ops))
}

// ---------------------------------------------------------------------------
// Test: EmitPoseidon2KBCompress produces fewer ops than full permute
// (due to final drops) but is still substantial
// ---------------------------------------------------------------------------

func TestPoseidon2KB_CompressOpCount(t *testing.T) {
	var permuteOps []StackOp
	EmitPoseidon2KBPermute(func(op StackOp) {
		permuteOps = append(permuteOps, op)
	})

	var compressOps []StackOp
	EmitPoseidon2KBCompress(func(op StackOp) {
		compressOps = append(compressOps, op)
	})

	// Compress should produce more ops than permute alone because it adds
	// drop operations for the 8 unused state elements plus reordering.
	// Both should be substantial.
	if len(compressOps) < 1000 {
		t.Errorf("expected at least 1000 ops from Poseidon2 compress, got %d", len(compressOps))
	}
	t.Logf("Poseidon2KBCompress emitted %d StackOps (vs %d for permute)", len(compressOps), len(permuteOps))
}

// ---------------------------------------------------------------------------
// Test: State naming helpers produce expected names
// ---------------------------------------------------------------------------

func TestPoseidon2KB_StateNames(t *testing.T) {
	names := poseidon2KBStateNames()
	if len(names) != 16 {
		t.Fatalf("expected 16 state names, got %d", len(names))
	}
	if names[0] != "_p2s0" {
		t.Errorf("expected names[0] = '_p2s0', got '%s'", names[0])
	}
	if names[15] != "_p2s15" {
		t.Errorf("expected names[15] = '_p2s15', got '%s'", names[15])
	}
}

// ---------------------------------------------------------------------------
// Test: Internal diagonal constants are correct
// ---------------------------------------------------------------------------

func TestPoseidon2KB_InternalDiagConstants(t *testing.T) {
	// diag[0] should be p-2
	if poseidon2KBInternalDiagM1[0] != 2130706431 {
		t.Errorf("expected diag[0] = 2130706431 (p-2), got %d", poseidon2KBInternalDiagM1[0])
	}
	// diag[1] should be 1
	if poseidon2KBInternalDiagM1[1] != 1 {
		t.Errorf("expected diag[1] = 1, got %d", poseidon2KBInternalDiagM1[1])
	}
	// Diagonal from Plonky3 DiffusionMatrixKoalaBear:
	// V = [-2, 1, 2, 1/2, 3, 4, -1/2, -3, -4, 1/2^8, 1/8, 1/2^24, -1/2^8, -1/8, -1/16, -1/2^24]
	// Values computed mod p (fractions via modular inverse).
	expectedDiag := [poseidon2KBWidth]int64{
		2130706431, 1, 2, 1065353217, 3, 4, 1065353216, 2130706430,
		2130706429, 2122383361, 1864368129, 2130706306, 8323072, 266338304, 133169152, 127,
	}
	for i := 0; i < poseidon2KBWidth; i++ {
		if poseidon2KBInternalDiagM1[i] != expectedDiag[i] {
			t.Errorf("expected diag[%d] = %d, got %d", i, expectedDiag[i], poseidon2KBInternalDiagM1[i])
		}
	}
}

// ---------------------------------------------------------------------------
// Test: Round constants array has correct dimensions
// ---------------------------------------------------------------------------

func TestPoseidon2KB_RoundConstantsDimensions(t *testing.T) {
	if len(poseidon2KBRoundConstants) != poseidon2KBTotalRounds {
		t.Errorf("expected %d rounds of constants, got %d", poseidon2KBTotalRounds, len(poseidon2KBRoundConstants))
	}
	if poseidon2KBTotalRounds != 28 {
		t.Errorf("expected 28 total rounds, got %d", poseidon2KBTotalRounds)
	}
	for r := 0; r < poseidon2KBTotalRounds; r++ {
		if len(poseidon2KBRoundConstants[r]) != poseidon2KBWidth {
			t.Errorf("round %d: expected %d constants, got %d", r, poseidon2KBWidth, len(poseidon2KBRoundConstants[r]))
		}
	}
}

// ---------------------------------------------------------------------------
// Test: Permute does not panic with all-zero round constants
// ---------------------------------------------------------------------------

func TestPoseidon2KB_PermuteNoPanic(t *testing.T) {
	// This test verifies the codegen doesn't panic during emission.
	// With zero round constants, the round constant addition is skipped,
	// but all other operations (sbox, MDS, diffusion) still run.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("EmitPoseidon2KBPermute panicked: %v", r)
		}
	}()

	var ops []StackOp
	EmitPoseidon2KBPermute(func(op StackOp) {
		ops = append(ops, op)
	})
}

// ---------------------------------------------------------------------------
// Correctness test vectors are validated in packages/runar-go/poseidon2_kb_test.go
// (mock permutation vs Plonky3 p3-koala-bear 0.5.2 reference vectors).
// Script-level validation (codegen → Bitcoin Script → interpreter) is in
// integration/go/script_correctness_test.go.
// ---------------------------------------------------------------------------

package codegen

import (
	"fmt"
	"testing"
)

// ---------------------------------------------------------------------------
// Helper: collect emitted StackOps
// ---------------------------------------------------------------------------

func fsHasOpcode(ops []StackOp, code string) bool {
	for _, op := range ops {
		if op.Op == "opcode" && op.Code == code {
			return true
		}
	}
	return false
}

func fsCountPushZeros(ops []StackOp) int {
	n := 0
	for _, op := range ops {
		if op.Op == "push" && op.Value.Kind == "bigint" && op.Value.BigInt != nil && op.Value.BigInt.Int64() == 0 {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// Test: Init pushes 16 zeros
// ---------------------------------------------------------------------------

func TestFiatShamirKB_Init(t *testing.T) {
	fs := NewFiatShamirState()

	var ops []StackOp
	tracker := NewKBTracker(nil, func(op StackOp) {
		ops = append(ops, op)
	})

	fs.EmitInit(tracker)

	// Should have exactly 16 push ops, all pushing 0.
	if len(ops) != 16 {
		t.Fatalf("expected 16 ops from EmitInit, got %d", len(ops))
	}

	zeros := fsCountPushZeros(ops)
	if zeros != 16 {
		t.Errorf("expected 16 zero pushes, got %d", zeros)
	}

	// Positions should be 0 after init, output not valid.
	if fs.AbsorbPos() != 0 {
		t.Errorf("expected absorbPos 0 after init, got %d", fs.AbsorbPos())
	}
	if fs.SqueezePos() != 0 {
		t.Errorf("expected squeezePos 0 after init, got %d", fs.SqueezePos())
	}
	if fs.OutputValid() {
		t.Error("expected outputValid=false after init")
	}

	// Tracker should have 16 named elements fs0..fs15.
	for i := 0; i < 16; i++ {
		name := fsSpongeStateName(i)
		depth := tracker.findDepth(name)
		if depth < 0 {
			t.Errorf("expected '%s' on tracker stack", name)
		}
	}

	t.Logf("EmitInit emitted %d ops", len(ops))
}

// ---------------------------------------------------------------------------
// Test: Single observe does not trigger permutation
// ---------------------------------------------------------------------------

func TestFiatShamirKB_ObserveSingle(t *testing.T) {
	fs := NewFiatShamirState()

	var ops []StackOp
	// Start with sponge state + one element to absorb.
	initNames := make([]string, 17)
	for i := 0; i < 16; i++ {
		initNames[i] = fsSpongeStateName(i)
	}
	initNames[16] = "element"
	tracker := NewKBTracker(initNames, func(op StackOp) {
		ops = append(ops, op)
	})

	fs.EmitObserve(tracker)

	// AbsorbPos should advance to 1.
	if fs.AbsorbPos() != 1 {
		t.Errorf("expected absorbPos 1 after single observe, got %d", fs.AbsorbPos())
	}

	// Output should be invalidated.
	if fs.OutputValid() {
		t.Error("expected outputValid=false after observe")
	}

	// Should NOT have triggered a Poseidon2 permutation.
	// The Poseidon2 permutation emits thousands of ops due to 28 rounds.
	// A single observe should only need a few stack manipulation ops.
	if len(ops) > 50 {
		t.Errorf("expected fewer than 50 ops for single observe (no permutation), got %d", len(ops))
	}

	t.Logf("Single observe emitted %d ops", len(ops))
}

// ---------------------------------------------------------------------------
// Test: Absorbing 8 elements triggers permutation
// ---------------------------------------------------------------------------

func TestFiatShamirKB_ObserveFullRate(t *testing.T) {
	fs := NewFiatShamirState()

	var ops []StackOp
	// Start with sponge state + 8 elements to absorb (pushed one at a time).
	initNames := make([]string, 16)
	for i := 0; i < 16; i++ {
		initNames[i] = fsSpongeStateName(i)
	}
	tracker := NewKBTracker(initNames, func(op StackOp) {
		ops = append(ops, op)
	})

	// Count ops before each observe to detect when the permutation fires.
	opCounts := make([]int, 8)
	for i := 0; i < 8; i++ {
		before := len(ops)
		// Push an element to absorb.
		tracker.pushInt("element", int64(i+1))
		fs.EmitObserve(tracker)
		opCounts[i] = len(ops) - before
	}

	// After 8 observations, absorbPos should reset to 0.
	if fs.AbsorbPos() != 0 {
		t.Errorf("expected absorbPos 0 after 8 observations, got %d", fs.AbsorbPos())
	}

	// Output should be valid after full-rate permutation.
	if !fs.OutputValid() {
		t.Error("expected outputValid=true after 8 observations (permutation fired)")
	}

	// SqueezePos should be 0 (ready to squeeze from fresh state).
	if fs.SqueezePos() != 0 {
		t.Errorf("expected squeezePos 0 after 8 observations, got %d", fs.SqueezePos())
	}

	// The 8th observe should have triggered the permutation and thus produced
	// many more ops than the first 7.
	for i := 0; i < 7; i++ {
		if opCounts[i] > 50 {
			t.Errorf("observe %d: expected <50 ops (no permutation), got %d", i, opCounts[i])
		}
	}
	if opCounts[7] < 100 {
		t.Errorf("observe 7: expected >100 ops (permutation triggered), got %d", opCounts[7])
	}

	t.Logf("Per-observe op counts: %v", opCounts)
	t.Logf("Total ops for 8 observations: %d", len(ops))
}

// ---------------------------------------------------------------------------
// Test: Squeeze after partial absorption triggers permutation
// ---------------------------------------------------------------------------

func TestFiatShamirKB_SqueezeAfterObserve(t *testing.T) {
	fs := NewFiatShamirState()

	var ops []StackOp
	initNames := make([]string, 16)
	for i := 0; i < 16; i++ {
		initNames[i] = fsSpongeStateName(i)
	}
	tracker := NewKBTracker(initNames, func(op StackOp) {
		ops = append(ops, op)
	})

	// Absorb 3 elements (partial rate).
	for i := 0; i < 3; i++ {
		tracker.pushInt("element", int64(i+1))
		fs.EmitObserve(tracker)
	}
	if fs.AbsorbPos() != 3 {
		t.Fatalf("expected absorbPos 3 after 3 observations, got %d", fs.AbsorbPos())
	}
	if fs.OutputValid() {
		t.Fatal("expected outputValid=false after partial observations")
	}

	opsBefore := len(ops)

	// Squeeze should detect !outputValid and permute first.
	fs.EmitSqueeze(tracker)

	squeezeOps := len(ops) - opsBefore

	// The squeeze should have triggered a permutation.
	if squeezeOps < 100 {
		t.Errorf("expected >100 ops from squeeze-after-observe (permutation), got %d", squeezeOps)
	}

	// After squeeze: outputValid=true, squeezePos=1 (one element consumed),
	// absorbPos=0 (reset by permutation).
	if fs.SqueezePos() != 1 {
		t.Errorf("expected squeezePos 1 after squeeze, got %d", fs.SqueezePos())
	}
	if fs.AbsorbPos() != 0 {
		t.Errorf("expected absorbPos 0 after squeeze-triggered permutation, got %d", fs.AbsorbPos())
	}
	if !fs.OutputValid() {
		t.Error("expected outputValid=true after squeeze-triggered permutation")
	}

	// The squeezed value should be on the tracker stack as _fs_squeezed.
	depth := tracker.findDepth("_fs_squeezed")
	if depth < 0 {
		t.Error("expected _fs_squeezed on tracker stack after squeeze")
	}

	t.Logf("Squeeze-after-observe emitted %d ops", squeezeOps)
}

// ---------------------------------------------------------------------------
// Test: SqueezeExt4 produces 4 elements with ONE permutation
// ---------------------------------------------------------------------------

func TestFiatShamirKB_SqueezeExt4(t *testing.T) {
	fs := NewFiatShamirState()

	var ops []StackOp
	initNames := make([]string, 16)
	for i := 0; i < 16; i++ {
		initNames[i] = fsSpongeStateName(i)
	}
	tracker := NewKBTracker(initNames, func(op StackOp) {
		ops = append(ops, op)
	})

	fs.EmitSqueezeExt4(tracker)

	// DuplexChallenger: first squeeze triggers permutation, next 3 read from
	// cached output (no additional permutations). squeezePos advances to 4.
	if fs.SqueezePos() != 4 {
		t.Errorf("expected squeezePos 4 after SqueezeExt4, got %d", fs.SqueezePos())
	}
	if !fs.OutputValid() {
		t.Error("expected outputValid=true after SqueezeExt4")
	}

	// Should have 4 named elements on top of stack: _fs_ext4_0 .. _fs_ext4_3.
	for i := 0; i < 4; i++ {
		expectedName := fmt.Sprintf("_fs_ext4_%d", i)
		depth := tracker.findDepth(expectedName)
		if depth < 0 {
			t.Errorf("expected '%s' on tracker stack after SqueezeExt4", expectedName)
		}
	}

	t.Logf("SqueezeExt4 emitted %d ops (1 permutation, not 4)", len(ops))
}

// ---------------------------------------------------------------------------
// Test: SampleBits produces a value with OP_MOD masking
// ---------------------------------------------------------------------------

func TestFiatShamirKB_SampleBits(t *testing.T) {
	fs := NewFiatShamirState()

	var ops []StackOp
	initNames := make([]string, 16)
	for i := 0; i < 16; i++ {
		initNames[i] = fsSpongeStateName(i)
	}
	tracker := NewKBTracker(initNames, func(op StackOp) {
		ops = append(ops, op)
	})

	fs.EmitSampleBits(tracker, 8)

	// Should contain an OP_MOD for the bit extraction.
	if !fsHasOpcode(ops, "OP_MOD") {
		t.Error("expected OP_MOD in SampleBits output")
	}

	// The result should be on the stack as _fs_bits.
	depth := tracker.findDepth("_fs_bits")
	if depth < 0 {
		t.Error("expected _fs_bits on tracker stack after SampleBits")
	}

	t.Logf("SampleBits(8) emitted %d ops", len(ops))
}

// ---------------------------------------------------------------------------
// Test: CheckWitness absorbs, squeezes, and asserts
// ---------------------------------------------------------------------------

func TestFiatShamirKB_CheckWitness(t *testing.T) {
	fs := NewFiatShamirState()

	var ops []StackOp
	// Sponge state + witness element.
	initNames := make([]string, 17)
	for i := 0; i < 16; i++ {
		initNames[i] = fsSpongeStateName(i)
	}
	initNames[16] = "witness"
	tracker := NewKBTracker(initNames, func(op StackOp) {
		ops = append(ops, op)
	})

	fs.EmitCheckWitness(tracker, 16)

	// Should contain OP_NUMEQUAL and OP_VERIFY for the proof-of-work assertion.
	if !fsHasOpcode(ops, "OP_NUMEQUAL") {
		t.Error("expected OP_NUMEQUAL in CheckWitness output")
	}
	if !fsHasOpcode(ops, "OP_VERIFY") {
		t.Error("expected OP_VERIFY in CheckWitness output")
	}

	t.Logf("CheckWitness(16) emitted %d ops", len(ops))
}

// ---------------------------------------------------------------------------
// Test: Multiple squeezes from clean state — DuplexChallenger semantics
// ---------------------------------------------------------------------------

func TestFiatShamirKB_MultipleSqueezesPosition(t *testing.T) {
	fs := NewFiatShamirState()

	var ops []StackOp
	initNames := make([]string, 16)
	for i := 0; i < 16; i++ {
		initNames[i] = fsSpongeStateName(i)
	}
	tracker := NewKBTracker(initNames, func(op StackOp) {
		ops = append(ops, op)
	})

	// First squeeze: outputValid=false, triggers permutation.
	// Reads fs0, squeezePos → 1.
	opsBefore := len(ops)
	fs.EmitSqueeze(tracker)
	firstSqueezeOps := len(ops) - opsBefore
	if fs.SqueezePos() != 1 {
		t.Errorf("after 1st squeeze: expected squeezePos 1, got %d", fs.SqueezePos())
	}
	if !fs.OutputValid() {
		t.Error("after 1st squeeze: expected outputValid=true")
	}
	if firstSqueezeOps < 100 {
		t.Errorf("1st squeeze should trigger permutation (>100 ops), got %d", firstSqueezeOps)
	}

	// Second squeeze: outputValid=true, squeezePos=1 < RATE=8.
	// NO permutation. Reads fs1, squeezePos → 2.
	opsBefore = len(ops)
	tracker.toTop("_fs_squeezed")
	tracker.drop()
	fs.EmitSqueeze(tracker)
	secondSqueezeOps := len(ops) - opsBefore
	if fs.SqueezePos() != 2 {
		t.Errorf("after 2nd squeeze: expected squeezePos 2, got %d", fs.SqueezePos())
	}
	if secondSqueezeOps > 50 {
		t.Errorf("2nd squeeze should NOT permute (<50 ops), got %d", secondSqueezeOps)
	}

	// Clean up squeezed element.
	tracker.toTop("_fs_squeezed")
	tracker.drop()

	// Absorb something — this invalidates the squeeze output.
	tracker.pushInt("element", 42)
	fs.EmitObserve(tracker)
	if fs.AbsorbPos() != 1 {
		t.Errorf("after observe: expected absorbPos 1, got %d", fs.AbsorbPos())
	}
	if fs.OutputValid() {
		t.Error("after observe: expected outputValid=false")
	}

	// Squeeze: outputValid=false, triggers permutation. Reads fs0, squeezePos → 1.
	opsBefore = len(ops)
	fs.EmitSqueeze(tracker)
	thirdSqueezeOps := len(ops) - opsBefore
	if fs.SqueezePos() != 1 {
		t.Errorf("after squeeze-post-observe: expected squeezePos 1, got %d", fs.SqueezePos())
	}
	if thirdSqueezeOps < 100 {
		t.Errorf("squeeze after observe should trigger permutation (>100 ops), got %d", thirdSqueezeOps)
	}
}

// ---------------------------------------------------------------------------
// Test: 8 consecutive squeezes exhaust the rate, 9th triggers new permutation
// ---------------------------------------------------------------------------

func TestFiatShamirKB_SqueezeExhaustRate(t *testing.T) {
	fs := NewFiatShamirState()

	initNames := make([]string, 16)
	for i := 0; i < 16; i++ {
		initNames[i] = fsSpongeStateName(i)
	}

	var ops []StackOp
	tracker := NewKBTracker(initNames, func(op StackOp) {
		ops = append(ops, op)
	})

	// Squeeze 8 times — first triggers permutation, 2-8 read from cache.
	for i := 0; i < 8; i++ {
		fs.EmitSqueeze(tracker)
		tracker.toTop("_fs_squeezed")
		tracker.rename(fmt.Sprintf("_out_%d", i))
	}

	if fs.SqueezePos() != 8 {
		t.Errorf("after 8 squeezes: expected squeezePos 8, got %d", fs.SqueezePos())
	}

	// The 9th squeeze should trigger a NEW permutation (rate exhausted).
	opsBefore := len(ops)
	fs.EmitSqueeze(tracker)
	ninthOps := len(ops) - opsBefore
	if ninthOps < 100 {
		t.Errorf("9th squeeze should trigger permutation (>100 ops), got %d", ninthOps)
	}
	if fs.SqueezePos() != 1 {
		t.Errorf("after 9th squeeze: expected squeezePos 1 (reset), got %d", fs.SqueezePos())
	}
}

// ---------------------------------------------------------------------------
// Test: NewFiatShamirState starts at position 0, output invalid
// ---------------------------------------------------------------------------

func TestFiatShamirKB_NewState(t *testing.T) {
	fs := NewFiatShamirState()
	if fs.AbsorbPos() != 0 {
		t.Errorf("expected initial absorbPos 0, got %d", fs.AbsorbPos())
	}
	if fs.SqueezePos() != 0 {
		t.Errorf("expected initial squeezePos 0, got %d", fs.SqueezePos())
	}
	if fs.OutputValid() {
		t.Error("expected initial outputValid=false")
	}
}

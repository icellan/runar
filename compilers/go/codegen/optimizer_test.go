package codegen

import (
	"math/big"
	"testing"
)

// ---------------------------------------------------------------------------
// Helper: create common StackOp values
// ---------------------------------------------------------------------------

func pushBigIntOp(n int64) StackOp {
	return StackOp{
		Op:    "push",
		Value: PushValue{Kind: "bigint", BigInt: big.NewInt(n)},
	}
}

func opcodeOp(code string) StackOp {
	return StackOp{Op: "opcode", Code: code}
}

// ---------------------------------------------------------------------------
// 2-op window: SWAP SWAP -> removed
// ---------------------------------------------------------------------------

func TestOptimizer_SwapSwap_Removed(t *testing.T) {
	ops := []StackOp{
		{Op: "swap"},
		{Op: "swap"},
	}
	result := OptimizeStackOps(ops)
	if len(result) != 0 {
		t.Errorf("SWAP SWAP should be removed entirely, got %d ops", len(result))
	}
}

// ---------------------------------------------------------------------------
// 2-op window: DUP DROP -> removed
// ---------------------------------------------------------------------------

func TestOptimizer_DupDrop_Removed(t *testing.T) {
	ops := []StackOp{
		{Op: "dup"},
		{Op: "drop"},
	}
	result := OptimizeStackOps(ops)
	if len(result) != 0 {
		t.Errorf("DUP DROP should be removed entirely, got %d ops", len(result))
	}
}

// ---------------------------------------------------------------------------
// 2-op window: OP_DUP OP_DROP -> removed
// ---------------------------------------------------------------------------

func TestOptimizer_OpcodeDupDrop_Removed(t *testing.T) {
	ops := []StackOp{
		opcodeOp("OP_DUP"),
		opcodeOp("OP_DROP"),
	}
	result := OptimizeStackOps(ops)
	if len(result) != 0 {
		t.Errorf("OP_DUP OP_DROP should be removed entirely, got %d ops", len(result))
	}
}

// ---------------------------------------------------------------------------
// 2-op window: PUSH x DROP -> removed (dead value elimination)
// ---------------------------------------------------------------------------

func TestOptimizer_PushDrop_Removed(t *testing.T) {
	ops := []StackOp{
		pushBigIntOp(42),
		{Op: "drop"},
	}
	result := OptimizeStackOps(ops)
	if len(result) != 0 {
		t.Errorf("PUSH DROP should be removed entirely, got %d ops", len(result))
	}
}

// ---------------------------------------------------------------------------
// 2-op window: PUSH(1) OP_ADD -> OP_1ADD
// ---------------------------------------------------------------------------

func TestOptimizer_Push1Add_Becomes1ADD(t *testing.T) {
	ops := []StackOp{
		pushBigIntOp(1),
		opcodeOp("OP_ADD"),
	}
	result := OptimizeStackOps(ops)
	if len(result) != 1 {
		t.Fatalf("expected 1 op, got %d", len(result))
	}
	if result[0].Op != "opcode" || result[0].Code != "OP_1ADD" {
		t.Errorf("expected OP_1ADD, got %s %s", result[0].Op, result[0].Code)
	}
}

// ---------------------------------------------------------------------------
// 2-op window: PUSH(1) OP_SUB -> OP_1SUB
// ---------------------------------------------------------------------------

func TestOptimizer_Push1Sub_Becomes1SUB(t *testing.T) {
	ops := []StackOp{
		pushBigIntOp(1),
		opcodeOp("OP_SUB"),
	}
	result := OptimizeStackOps(ops)
	if len(result) != 1 {
		t.Fatalf("expected 1 op, got %d", len(result))
	}
	if result[0].Op != "opcode" || result[0].Code != "OP_1SUB" {
		t.Errorf("expected OP_1SUB, got %s %s", result[0].Op, result[0].Code)
	}
}

// ---------------------------------------------------------------------------
// 2-op window: PUSH(0) OP_ADD -> removed (identity)
// ---------------------------------------------------------------------------

func TestOptimizer_Push0Add_Removed(t *testing.T) {
	ops := []StackOp{
		pushBigIntOp(0),
		opcodeOp("OP_ADD"),
	}
	result := OptimizeStackOps(ops)
	if len(result) != 0 {
		t.Errorf("PUSH(0) OP_ADD should be removed, got %d ops", len(result))
	}
}

// ---------------------------------------------------------------------------
// 2-op window: OP_NOT OP_NOT -> removed (double negation)
// ---------------------------------------------------------------------------

func TestOptimizer_DoubleNot_Removed(t *testing.T) {
	ops := []StackOp{
		opcodeOp("OP_NOT"),
		opcodeOp("OP_NOT"),
	}
	result := OptimizeStackOps(ops)
	if len(result) != 0 {
		t.Errorf("OP_NOT OP_NOT should be removed, got %d ops", len(result))
	}
}

// ---------------------------------------------------------------------------
// 2-op window: OP_NEGATE OP_NEGATE -> removed
// ---------------------------------------------------------------------------

func TestOptimizer_DoubleNegate_Removed(t *testing.T) {
	ops := []StackOp{
		opcodeOp("OP_NEGATE"),
		opcodeOp("OP_NEGATE"),
	}
	result := OptimizeStackOps(ops)
	if len(result) != 0 {
		t.Errorf("OP_NEGATE OP_NEGATE should be removed, got %d ops", len(result))
	}
}

// ---------------------------------------------------------------------------
// 2-op window: OP_EQUAL OP_VERIFY -> OP_EQUALVERIFY
// ---------------------------------------------------------------------------

func TestOptimizer_EqualVerify_Merged(t *testing.T) {
	ops := []StackOp{
		opcodeOp("OP_EQUAL"),
		opcodeOp("OP_VERIFY"),
	}
	result := OptimizeStackOps(ops)
	if len(result) != 1 {
		t.Fatalf("expected 1 op, got %d", len(result))
	}
	if result[0].Code != "OP_EQUALVERIFY" {
		t.Errorf("expected OP_EQUALVERIFY, got %s", result[0].Code)
	}
}

// ---------------------------------------------------------------------------
// 2-op window: OP_CHECKSIG OP_VERIFY -> OP_CHECKSIGVERIFY
// ---------------------------------------------------------------------------

func TestOptimizer_CheckSigVerify_Merged(t *testing.T) {
	ops := []StackOp{
		opcodeOp("OP_CHECKSIG"),
		opcodeOp("OP_VERIFY"),
	}
	result := OptimizeStackOps(ops)
	if len(result) != 1 {
		t.Fatalf("expected 1 op, got %d", len(result))
	}
	if result[0].Code != "OP_CHECKSIGVERIFY" {
		t.Errorf("expected OP_CHECKSIGVERIFY, got %s", result[0].Code)
	}
}

// ---------------------------------------------------------------------------
// 2-op window: OP_NUMEQUAL OP_VERIFY -> OP_NUMEQUALVERIFY
// ---------------------------------------------------------------------------

func TestOptimizer_NumEqualVerify_Merged(t *testing.T) {
	ops := []StackOp{
		opcodeOp("OP_NUMEQUAL"),
		opcodeOp("OP_VERIFY"),
	}
	result := OptimizeStackOps(ops)
	if len(result) != 1 {
		t.Fatalf("expected 1 op, got %d", len(result))
	}
	if result[0].Code != "OP_NUMEQUALVERIFY" {
		t.Errorf("expected OP_NUMEQUALVERIFY, got %s", result[0].Code)
	}
}

// ---------------------------------------------------------------------------
// 2-op window: DROP DROP -> OP_2DROP
// ---------------------------------------------------------------------------

func TestOptimizer_DropDrop_Becomes2DROP(t *testing.T) {
	ops := []StackOp{
		{Op: "drop"},
		{Op: "drop"},
	}
	result := OptimizeStackOps(ops)
	if len(result) != 1 {
		t.Fatalf("expected 1 op, got %d", len(result))
	}
	if result[0].Code != "OP_2DROP" {
		t.Errorf("expected OP_2DROP, got %s %s", result[0].Op, result[0].Code)
	}
}

// ---------------------------------------------------------------------------
// 2-op window: OVER OVER -> OP_2DUP
// ---------------------------------------------------------------------------

func TestOptimizer_OverOver_Becomes2DUP(t *testing.T) {
	ops := []StackOp{
		{Op: "over"},
		{Op: "over"},
	}
	result := OptimizeStackOps(ops)
	if len(result) != 1 {
		t.Fatalf("expected 1 op, got %d", len(result))
	}
	if result[0].Code != "OP_2DUP" {
		t.Errorf("expected OP_2DUP, got %s %s", result[0].Op, result[0].Code)
	}
}

// ---------------------------------------------------------------------------
// 2-op window: PUSH(0) ROLL -> removed (roll 0 is no-op)
// ---------------------------------------------------------------------------

func TestOptimizer_Push0Roll_Removed(t *testing.T) {
	ops := []StackOp{
		pushBigIntOp(0),
		{Op: "roll"},
	}
	result := OptimizeStackOps(ops)
	if len(result) != 0 {
		t.Errorf("PUSH(0) ROLL should be removed, got %d ops", len(result))
	}
}

// ---------------------------------------------------------------------------
// 2-op window: PUSH(1) ROLL -> SWAP
// ---------------------------------------------------------------------------

func TestOptimizer_Push1Roll_BecomesSwap(t *testing.T) {
	ops := []StackOp{
		pushBigIntOp(1),
		{Op: "roll"},
	}
	result := OptimizeStackOps(ops)
	if len(result) != 1 {
		t.Fatalf("expected 1 op, got %d", len(result))
	}
	if result[0].Op != "swap" {
		t.Errorf("expected swap, got %s", result[0].Op)
	}
}

// ---------------------------------------------------------------------------
// 2-op window: PUSH(2) ROLL -> ROT
// ---------------------------------------------------------------------------

func TestOptimizer_Push2Roll_BecomesRot(t *testing.T) {
	ops := []StackOp{
		pushBigIntOp(2),
		{Op: "roll", Depth: 2},
	}
	result := OptimizeStackOps(ops)
	if len(result) != 1 {
		t.Fatalf("expected 1 op, got %d", len(result))
	}
	if result[0].Op != "rot" {
		t.Errorf("expected rot, got %s", result[0].Op)
	}
}

// ---------------------------------------------------------------------------
// 2-op window: PUSH(0) PICK -> DUP
// ---------------------------------------------------------------------------

func TestOptimizer_Push0Pick_BecomesDup(t *testing.T) {
	ops := []StackOp{
		pushBigIntOp(0),
		{Op: "pick"},
	}
	result := OptimizeStackOps(ops)
	if len(result) != 1 {
		t.Fatalf("expected 1 op, got %d", len(result))
	}
	if result[0].Op != "dup" {
		t.Errorf("expected dup, got %s", result[0].Op)
	}
}

// ---------------------------------------------------------------------------
// 2-op window: PUSH(1) PICK -> OVER
// ---------------------------------------------------------------------------

func TestOptimizer_Push1Pick_BecomesOver(t *testing.T) {
	ops := []StackOp{
		pushBigIntOp(1),
		{Op: "pick"},
	}
	result := OptimizeStackOps(ops)
	if len(result) != 1 {
		t.Fatalf("expected 1 op, got %d", len(result))
	}
	if result[0].Op != "over" {
		t.Errorf("expected over, got %s", result[0].Op)
	}
}

// ---------------------------------------------------------------------------
// 2-op window: OP_SHA256 OP_SHA256 -> OP_HASH256
// ---------------------------------------------------------------------------

func TestOptimizer_DoubleSHA256_BecomesHASH256(t *testing.T) {
	ops := []StackOp{
		opcodeOp("OP_SHA256"),
		opcodeOp("OP_SHA256"),
	}
	result := OptimizeStackOps(ops)
	if len(result) != 1 {
		t.Fatalf("expected 1 op, got %d", len(result))
	}
	if result[0].Code != "OP_HASH256" {
		t.Errorf("expected OP_HASH256, got %s", result[0].Code)
	}
}

// ---------------------------------------------------------------------------
// 2-op window: PUSH(0) OP_NUMEQUAL -> OP_NOT
// ---------------------------------------------------------------------------

func TestOptimizer_Push0NumEqual_BecomesNot(t *testing.T) {
	ops := []StackOp{
		pushBigIntOp(0),
		opcodeOp("OP_NUMEQUAL"),
	}
	result := OptimizeStackOps(ops)
	if len(result) != 1 {
		t.Fatalf("expected 1 op, got %d", len(result))
	}
	if result[0].Code != "OP_NOT" {
		t.Errorf("expected OP_NOT, got %s", result[0].Code)
	}
}

// ---------------------------------------------------------------------------
// 3-op window: PUSH(3) PUSH(4) OP_ADD -> PUSH(7)
// ---------------------------------------------------------------------------

func TestOptimizer_ConstFold_Add(t *testing.T) {
	ops := []StackOp{
		pushBigIntOp(3),
		pushBigIntOp(4),
		opcodeOp("OP_ADD"),
	}
	result := OptimizeStackOps(ops)
	if len(result) != 1 {
		t.Fatalf("expected 1 op after constant folding, got %d", len(result))
	}
	if result[0].Op != "push" || result[0].Value.BigInt == nil {
		t.Fatalf("expected push bigint, got %s", result[0].Op)
	}
	if result[0].Value.BigInt.Cmp(big.NewInt(7)) != 0 {
		t.Errorf("expected 7, got %s", result[0].Value.BigInt.String())
	}
}

// ---------------------------------------------------------------------------
// 3-op window: PUSH(10) PUSH(3) OP_SUB -> PUSH(7)
// ---------------------------------------------------------------------------

func TestOptimizer_ConstFold_Sub(t *testing.T) {
	ops := []StackOp{
		pushBigIntOp(10),
		pushBigIntOp(3),
		opcodeOp("OP_SUB"),
	}
	result := OptimizeStackOps(ops)
	if len(result) != 1 {
		t.Fatalf("expected 1 op after constant folding, got %d", len(result))
	}
	if result[0].Value.BigInt.Cmp(big.NewInt(7)) != 0 {
		t.Errorf("expected 7, got %s", result[0].Value.BigInt.String())
	}
}

// ---------------------------------------------------------------------------
// 3-op window: PUSH(5) PUSH(6) OP_MUL -> PUSH(30)
// ---------------------------------------------------------------------------

func TestOptimizer_ConstFold_Mul(t *testing.T) {
	ops := []StackOp{
		pushBigIntOp(5),
		pushBigIntOp(6),
		opcodeOp("OP_MUL"),
	}
	result := OptimizeStackOps(ops)
	if len(result) != 1 {
		t.Fatalf("expected 1 op after constant folding, got %d", len(result))
	}
	if result[0].Value.BigInt.Cmp(big.NewInt(30)) != 0 {
		t.Errorf("expected 30, got %s", result[0].Value.BigInt.String())
	}
}

// ---------------------------------------------------------------------------
// 4-op window: PUSH(3) OP_ADD PUSH(5) OP_ADD -> PUSH(8) OP_ADD
// ---------------------------------------------------------------------------

func TestOptimizer_ChainFold_AddAdd(t *testing.T) {
	ops := []StackOp{
		pushBigIntOp(3),
		opcodeOp("OP_ADD"),
		pushBigIntOp(5),
		opcodeOp("OP_ADD"),
	}
	result := OptimizeStackOps(ops)
	if len(result) != 2 {
		t.Fatalf("expected 2 ops after chain folding, got %d", len(result))
	}
	if result[0].Op != "push" || result[0].Value.BigInt.Cmp(big.NewInt(8)) != 0 {
		t.Errorf("expected PUSH(8), got %v", result[0])
	}
	if result[1].Op != "opcode" || result[1].Code != "OP_ADD" {
		t.Errorf("expected OP_ADD, got %s %s", result[1].Op, result[1].Code)
	}
}

// ---------------------------------------------------------------------------
// 4-op window: PUSH(3) OP_SUB PUSH(5) OP_SUB -> PUSH(8) OP_SUB
// ---------------------------------------------------------------------------

func TestOptimizer_ChainFold_SubSub(t *testing.T) {
	ops := []StackOp{
		pushBigIntOp(3),
		opcodeOp("OP_SUB"),
		pushBigIntOp(5),
		opcodeOp("OP_SUB"),
	}
	result := OptimizeStackOps(ops)
	if len(result) != 2 {
		t.Fatalf("expected 2 ops after chain folding, got %d", len(result))
	}
	if result[0].Value.BigInt.Cmp(big.NewInt(8)) != 0 {
		t.Errorf("expected PUSH(8), got %s", result[0].Value.BigInt.String())
	}
	if result[1].Code != "OP_SUB" {
		t.Errorf("expected OP_SUB, got %s", result[1].Code)
	}
}

// ---------------------------------------------------------------------------
// Non-optimizable sequence passes through unchanged
// ---------------------------------------------------------------------------

func TestOptimizer_Passthrough_Unchanged(t *testing.T) {
	ops := []StackOp{
		opcodeOp("OP_DUP"),
		opcodeOp("OP_HASH160"),
		opcodeOp("OP_EQUALVERIFY"),
		opcodeOp("OP_CHECKSIG"),
	}
	result := OptimizeStackOps(ops)
	if len(result) != 4 {
		t.Fatalf("expected 4 ops unchanged, got %d", len(result))
	}
	expected := []string{"OP_DUP", "OP_HASH160", "OP_EQUALVERIFY", "OP_CHECKSIG"}
	for i, exp := range expected {
		if result[i].Code != exp {
			t.Errorf("op[%d]: expected %s, got %s", i, exp, result[i].Code)
		}
	}
}

// ---------------------------------------------------------------------------
// Opcode("OP_ROLL") string form — SLH-DSA emits these as opcode strings
// rather than typed Roll ops. Verify they pass through without crashing.
// ---------------------------------------------------------------------------

func TestOptimizer_OpcodeStringROLL_Passthrough(t *testing.T) {
	ops := []StackOp{
		opcodeOp("OP_DUP"),
		opcodeOp("OP_ROLL"),
		opcodeOp("OP_PICK"),
		opcodeOp("OP_ADD"),
	}
	result := OptimizeStackOps(ops)
	// These should pass through unchanged — OP_ROLL/OP_PICK as opcode strings
	// don't match the typed "roll"/"pick" ops used in 2-op window rules.
	if len(result) != 4 {
		t.Fatalf("expected 4 ops, got %d", len(result))
	}
	if result[1].Code != "OP_ROLL" {
		t.Errorf("expected OP_ROLL, got %s", result[1].Code)
	}
	if result[2].Code != "OP_PICK" {
		t.Errorf("expected OP_PICK, got %s", result[2].Code)
	}
}

// ---------------------------------------------------------------------------
// Nested if-block optimization — rules should apply inside if/else branches
// ---------------------------------------------------------------------------

func TestOptimizer_NestedIf_Optimized(t *testing.T) {
	ops := []StackOp{
		{
			Op: "if",
			Then: []StackOp{
				{Op: "swap"},
				{Op: "swap"},
				opcodeOp("OP_ADD"),
			},
			Else: []StackOp{
				opcodeOp("OP_CHECKSIG"),
				opcodeOp("OP_VERIFY"),
			},
		},
	}
	result := OptimizeStackOps(ops)
	if len(result) != 1 {
		t.Fatalf("expected 1 if op, got %d", len(result))
	}
	ifOp := result[0]
	if ifOp.Op != "if" {
		t.Fatalf("expected if op, got %s", ifOp.Op)
	}
	// Then: SWAP SWAP removed, only OP_ADD remains
	if len(ifOp.Then) != 1 {
		t.Errorf("then branch: expected 1 op (OP_ADD), got %d", len(ifOp.Then))
	} else if ifOp.Then[0].Code != "OP_ADD" {
		t.Errorf("then branch: expected OP_ADD, got %s", ifOp.Then[0].Code)
	}
	// Else: CHECKSIG + VERIFY -> CHECKSIGVERIFY
	if len(ifOp.Else) != 1 {
		t.Errorf("else branch: expected 1 op (OP_CHECKSIGVERIFY), got %d", len(ifOp.Else))
	} else if ifOp.Else[0].Code != "OP_CHECKSIGVERIFY" {
		t.Errorf("else branch: expected OP_CHECKSIGVERIFY, got %s", ifOp.Else[0].Code)
	}
}

// ---------------------------------------------------------------------------
// 2-op window: PUSH(0) OP_SUB -> removed (subtractive identity)
// ---------------------------------------------------------------------------

func TestOptimizer_Push0Sub_Removed(t *testing.T) {
	ops := []StackOp{
		pushBigIntOp(0),
		opcodeOp("OP_SUB"),
	}
	result := OptimizeStackOps(ops)
	if len(result) != 0 {
		t.Errorf("PUSH(0) OP_SUB should be removed (x - 0 = x), got %d ops", len(result))
	}
}

// ---------------------------------------------------------------------------
// 2-op window: OP_CHECKMULTISIG OP_VERIFY -> OP_CHECKMULTISIGVERIFY
// ---------------------------------------------------------------------------

func TestOptimizer_CheckMultiSigVerify_Merged(t *testing.T) {
	ops := []StackOp{
		opcodeOp("OP_CHECKMULTISIG"),
		opcodeOp("OP_VERIFY"),
	}
	result := OptimizeStackOps(ops)
	if len(result) != 1 {
		t.Fatalf("expected 1 op, got %d", len(result))
	}
	if result[0].Code != "OP_CHECKMULTISIGVERIFY" {
		t.Errorf("expected OP_CHECKMULTISIGVERIFY, got %s", result[0].Code)
	}
}

// ---------------------------------------------------------------------------
// 2-op window: PUSH(bool) DROP -> removed (any push followed by drop is eliminated)
// ---------------------------------------------------------------------------

func TestOptimizer_PushBoolDrop_Removed(t *testing.T) {
	ops := []StackOp{
		{Op: "push", Value: PushValue{Kind: "bool", Bool: true}},
		{Op: "drop"},
	}
	result := OptimizeStackOps(ops)
	if len(result) != 0 {
		t.Errorf("PUSH(bool) DROP should be removed entirely, got %d ops", len(result))
	}
}

// ---------------------------------------------------------------------------
// 3-op window: PUSH(6) PUSH(2) OP_DIV — NOT constant-folded (division not in rules)
// ---------------------------------------------------------------------------

func TestOptimizer_ConstFoldDivNotFolded(t *testing.T) {
	ops := []StackOp{
		pushBigIntOp(6),
		pushBigIntOp(2),
		opcodeOp("OP_DIV"),
	}
	result := OptimizeStackOps(ops)
	if len(result) != 3 {
		t.Errorf("PUSH PUSH DIV should NOT be constant-folded (3 ops unchanged), got %d ops", len(result))
	}
}

// ---------------------------------------------------------------------------
// 2-op window: PUSH(bytes) DROP -> removed
// ---------------------------------------------------------------------------

func TestOptimizer_PushBytesDrop_Removed(t *testing.T) {
	ops := []StackOp{
		{Op: "push", Value: PushValue{Kind: "bytes", Bytes: []byte{0xde, 0xad, 0xbe, 0xef}}},
		{Op: "drop"},
	}
	result := OptimizeStackOps(ops)
	if len(result) != 0 {
		t.Errorf("PUSH(bytes) DROP should be removed entirely, got %d ops", len(result))
	}
}

// ---------------------------------------------------------------------------
// 2-op window: PUSH(-1) DROP -> removed
// ---------------------------------------------------------------------------

func TestOptimizer_PushNegativeOneDrop_Removed(t *testing.T) {
	ops := []StackOp{
		pushBigIntOp(-1),
		{Op: "drop"},
	}
	result := OptimizeStackOps(ops)
	if len(result) != 0 {
		t.Errorf("PUSH(-1) DROP should be removed entirely, got %d ops", len(result))
	}
}

// ---------------------------------------------------------------------------
// 3-op window: PUSH(3) PUSH(10) OP_SUB -> PUSH(-7) (stack: top-1 - top = 3 - 10)
// ---------------------------------------------------------------------------

func TestOptimizer_ConstFoldSub_Negative(t *testing.T) {
	ops := []StackOp{
		pushBigIntOp(3),
		pushBigIntOp(10),
		opcodeOp("OP_SUB"),
	}
	result := OptimizeStackOps(ops)
	if len(result) != 1 {
		t.Fatalf("expected 1 op after constant folding, got %d", len(result))
	}
	if result[0].Op != "push" || result[0].Value.BigInt == nil {
		t.Fatalf("expected push bigint, got %s", result[0].Op)
	}
	if result[0].Value.BigInt.Cmp(big.NewInt(-7)) != 0 {
		t.Errorf("expected -7 (3 - 10), got %s", result[0].Value.BigInt.String())
	}
}

// ---------------------------------------------------------------------------
// 3-op window: PUSH(1000) PUSH(999) OP_ADD -> PUSH(1999)
// ---------------------------------------------------------------------------

func TestOptimizer_ConstFoldAdd_LargeValues(t *testing.T) {
	ops := []StackOp{
		pushBigIntOp(1000),
		pushBigIntOp(999),
		opcodeOp("OP_ADD"),
	}
	result := OptimizeStackOps(ops)
	if len(result) != 1 {
		t.Fatalf("expected 1 op after constant folding, got %d", len(result))
	}
	if result[0].Op != "push" || result[0].Value.BigInt == nil {
		t.Fatalf("expected push bigint, got %s", result[0].Op)
	}
	if result[0].Value.BigInt.Cmp(big.NewInt(1999)) != 0 {
		t.Errorf("expected 1999, got %s", result[0].Value.BigInt.String())
	}
}

// ---------------------------------------------------------------------------
// Iterative optimization — multi-pass convergence
// ---------------------------------------------------------------------------

func TestOptimizer_MultiPass_Convergence(t *testing.T) {
	// PUSH(0) OP_ADD produces nothing in pass 1.
	// Then SWAP SWAP from the remaining ops is removed in pass 2.
	ops := []StackOp{
		pushBigIntOp(0),
		opcodeOp("OP_ADD"),
		{Op: "swap"},
		{Op: "swap"},
		opcodeOp("OP_CHECKSIG"),
	}
	result := OptimizeStackOps(ops)
	if len(result) != 1 {
		t.Fatalf("expected 1 op after multi-pass, got %d", len(result))
	}
	if result[0].Code != "OP_CHECKSIG" {
		t.Errorf("expected OP_CHECKSIG, got %s", result[0].Code)
	}
}

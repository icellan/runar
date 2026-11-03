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
// F-001: PUSH(0) OP_ADD must survive. x + 0 = x over integers, but OP_ADD
// also decodes its operand as a CScriptNum (rejecting a non-minimal encoding
// under strict rules) and re-encodes it minimally; a witness operand gets no
// other normalisation, so deleting the pair changes accept/reject and value.
// Proves the Go peephole keeps the pair; does not execute a script (the TS
// peephole-exhaustive sweep does that against @bsv/sdk).
// ---------------------------------------------------------------------------

func TestOptimizer_Push0Add_Survives(t *testing.T) {
	ops := []StackOp{
		pushBigIntOp(0),
		opcodeOp("OP_ADD"),
	}
	result := OptimizeStackOps(ops)
	if len(result) != 2 || !isPushBigInt(result[0], 0) || result[1].Code != "OP_ADD" {
		t.Errorf("PUSH(0) OP_ADD must survive (F-001: OP_ADD validates/normalises its operand), got %+v", result)
	}
}

// ---------------------------------------------------------------------------
// 3-op window: <canonical-bool producer> OP_NOT OP_NOT -> producer
//
// C17: the pair is boolean normalisation, not numeric identity, so it is only
// removable when the value beneath is provably canonical (0/1). A bare pair
// with no visible producer must survive.
// ---------------------------------------------------------------------------

func TestOptimizer_DoubleNot_Removed(t *testing.T) {
	ops := []StackOp{
		opcodeOp("OP_NUMEQUAL"),
		opcodeOp("OP_NOT"),
		opcodeOp("OP_NOT"),
	}
	result := OptimizeStackOps(ops)
	if len(result) != 1 || result[0].Code != "OP_NUMEQUAL" {
		t.Errorf("OP_NUMEQUAL OP_NOT OP_NOT should reduce to OP_NUMEQUAL, got %d ops", len(result))
	}
}

func TestOptimizer_DoubleNot_BarePair_Survives(t *testing.T) {
	ops := []StackOp{
		opcodeOp("OP_NOT"),
		opcodeOp("OP_NOT"),
	}
	result := OptimizeStackOps(ops)
	if len(result) != 2 {
		t.Errorf("a bare OP_NOT OP_NOT pair must survive (operand provenance unknown), got %d ops", len(result))
	}
}

// ---------------------------------------------------------------------------
// F-001: OP_NEGATE OP_NEGATE must survive — same reason as PUSH(0) OP_ADD.
// ---------------------------------------------------------------------------

func TestOptimizer_DoubleNegate_Survives(t *testing.T) {
	ops := []StackOp{
		opcodeOp("OP_NEGATE"),
		opcodeOp("OP_NEGATE"),
	}
	result := OptimizeStackOps(ops)
	if len(result) != 2 || result[0].Code != "OP_NEGATE" || result[1].Code != "OP_NEGATE" {
		t.Errorf("OP_NEGATE OP_NEGATE must survive (F-001: OP_NEGATE validates/normalises its operand), got %+v", result)
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
		{Op: "roll", Depth: 1},
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
		{Op: "pick", Depth: 1},
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
// F-392: PUSH(depth) + opcode-string OP_ROLL/OP_PICK fold the same as the
// typed roll/pick form, at the three depths the typed rules cover. Matches
// compilers/python/runar_compiler/codegen/optimizer.py and
// compilers/ruby/.../optimizer.rb, which already accept both forms.
// ---------------------------------------------------------------------------

func TestOptimizer_Push0OpcodeStringRoll_Removed(t *testing.T) {
	ops := []StackOp{
		pushBigIntOp(0),
		opcodeOp("OP_ROLL"),
	}
	result := OptimizeStackOps(ops)
	if len(result) != 0 {
		t.Errorf("PUSH(0) opcode-string OP_ROLL should be removed, got %d ops", len(result))
	}
}

func TestOptimizer_Push1OpcodeStringRoll_BecomesSwap(t *testing.T) {
	ops := []StackOp{
		pushBigIntOp(1),
		opcodeOp("OP_ROLL"),
	}
	result := OptimizeStackOps(ops)
	if len(result) != 1 || result[0].Op != "swap" {
		t.Fatalf("expected [swap], got %v", result)
	}
}

func TestOptimizer_Push2OpcodeStringRoll_BecomesRot(t *testing.T) {
	ops := []StackOp{
		pushBigIntOp(2),
		opcodeOp("OP_ROLL"),
	}
	result := OptimizeStackOps(ops)
	if len(result) != 1 || result[0].Op != "rot" {
		t.Fatalf("expected [rot], got %v", result)
	}
}

func TestOptimizer_Push0OpcodeStringPick_BecomesDup(t *testing.T) {
	ops := []StackOp{
		pushBigIntOp(0),
		opcodeOp("OP_PICK"),
	}
	result := OptimizeStackOps(ops)
	if len(result) != 1 || result[0].Op != "dup" {
		t.Fatalf("expected [dup], got %v", result)
	}
}

func TestOptimizer_Push1OpcodeStringPick_BecomesOver(t *testing.T) {
	ops := []StackOp{
		pushBigIntOp(1),
		opcodeOp("OP_PICK"),
	}
	result := OptimizeStackOps(ops)
	if len(result) != 1 || result[0].Op != "over" {
		t.Fatalf("expected [over], got %v", result)
	}
}

// Depths the typed rules do NOT cover still pass through unreduced in
// opcode-string form too -- this item only teaches existing rules a second
// input representation, it does not add new depths.
func TestOptimizer_Push2OpcodeStringPick_Untouched(t *testing.T) {
	ops := []StackOp{
		pushBigIntOp(2),
		opcodeOp("OP_PICK"),
	}
	result := OptimizeStackOps(ops)
	if len(result) != 2 {
		t.Fatalf("expected passthrough (2 ops), got %v", result)
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
// F-001: PUSH(0) OP_SUB must survive — same reason as PUSH(0) OP_ADD.
// ---------------------------------------------------------------------------

func TestOptimizer_Push0Sub_Survives(t *testing.T) {
	ops := []StackOp{
		pushBigIntOp(0),
		opcodeOp("OP_SUB"),
	}
	result := OptimizeStackOps(ops)
	if len(result) != 2 || !isPushBigInt(result[0], 0) || result[1].Code != "OP_SUB" {
		t.Errorf("PUSH(0) OP_SUB must survive (F-001: OP_SUB validates/normalises its operand), got %+v", result)
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
	// PUSH(7) DROP produces nothing in pass 1, leaving SWAP SWAP adjacent.
	// Then SWAP SWAP is removed in pass 2. (Was PUSH(0) OP_ADD, which F-001
	// no longer eliminates.)
	ops := []StackOp{
		{Op: "swap"},
		pushBigIntOp(7),
		{Op: "drop"},
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

// ---------------------------------------------------------------------------
// Depth-safety: PUSH(1) ROLL{depth=5} — value and depth do not match,
// the optimizer must leave this untouched. Parity with TS, which checks
// `depth === 1` before collapsing to SWAP.
// ---------------------------------------------------------------------------

func TestOptimizer_Push1Roll_MismatchedDepth_Untouched(t *testing.T) {
	ops := []StackOp{
		pushBigIntOp(1),
		{Op: "roll", Depth: 5},
	}
	result := OptimizeStackOps(ops)
	if len(result) != 2 {
		t.Fatalf("expected 2 ops unchanged (value/depth mismatch), got %d", len(result))
	}
	if result[0].Op != "push" || result[1].Op != "roll" {
		t.Errorf("expected [push, roll], got [%s, %s]", result[0].Op, result[1].Op)
	}
	if result[1].Depth != 5 {
		t.Errorf("expected roll depth 5, got %d", result[1].Depth)
	}
}

// ---------------------------------------------------------------------------
// Depth-safety: PUSH(0) PICK{depth=3} — must be left alone.
// ---------------------------------------------------------------------------

func TestOptimizer_Push0Pick_MismatchedDepth_Untouched(t *testing.T) {
	ops := []StackOp{
		pushBigIntOp(0),
		{Op: "pick", Depth: 3},
	}
	result := OptimizeStackOps(ops)
	if len(result) != 2 {
		t.Fatalf("expected 2 ops unchanged (value/depth mismatch), got %d", len(result))
	}
	if result[0].Op != "push" || result[1].Op != "pick" {
		t.Errorf("expected [push, pick], got [%s, %s]", result[0].Op, result[1].Op)
	}
	if result[1].Depth != 3 {
		t.Errorf("expected pick depth 3, got %d", result[1].Depth)
	}
}

// ---------------------------------------------------------------------------
// Depth-safety: PUSH(2) ROLL{depth=1} — must be left alone.
// ---------------------------------------------------------------------------

func TestOptimizer_Push2Roll_MismatchedDepth_Untouched(t *testing.T) {
	ops := []StackOp{
		pushBigIntOp(2),
		{Op: "roll", Depth: 1},
	}
	result := OptimizeStackOps(ops)
	// PUSH(1)/Roll{depth=1} would collapse to SWAP, but here the pushed
	// value is 2, so neither the "PUSH(2)+Roll{2}" nor the "PUSH(1)+Roll{1}"
	// rule fires. Both ops should pass through.
	if len(result) != 2 {
		t.Fatalf("expected 2 ops unchanged (value/depth mismatch), got %d", len(result))
	}
	if result[0].Op != "push" || result[1].Op != "roll" {
		t.Errorf("expected [push, roll], got [%s, %s]", result[0].Op, result[1].Op)
	}
}

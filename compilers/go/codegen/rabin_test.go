package codegen

import (
	"math/big"
	"testing"
)

// rabinGolden is the fixed 15-opcode Rabin verification sequence:
// (sig^2 + padding) mod pubKey == SHA256(msg) AND 0 <= padding < 65536.
// See _review/BUG-010-rfc.md.
var rabinGolden = []struct {
	op    string
	code  string
	value int64 // only meaningful for op="push" (always bigint, int64-representable)
}{
	{op: "opcode", code: "OP_SWAP"},
	{op: "opcode", code: "OP_DUP"},
	{op: "opcode", code: "OP_0"},
	{op: "push", value: 65536},
	{op: "opcode", code: "OP_WITHIN"},
	{op: "opcode", code: "OP_VERIFY"},
	{op: "opcode", code: "OP_ROT"},
	{op: "opcode", code: "OP_DUP"},
	{op: "opcode", code: "OP_MUL"},
	{op: "opcode", code: "OP_ADD"},
	{op: "opcode", code: "OP_SWAP"},
	{op: "opcode", code: "OP_MOD"},
	{op: "opcode", code: "OP_SWAP"},
	{op: "opcode", code: "OP_SHA256"},
	{op: "opcode", code: "OP_EQUAL"},
}

// TestEmitVerifyRabinSig_ByteFrozenGolden pins the exact opcode sequence
// emitted by the extracted rabin.go module. Updated for BUG-010: the
// emission now includes a 5-opcode OP_WITHIN range check on `padding`.
func TestEmitVerifyRabinSig_ByteFrozenGolden(t *testing.T) {
	var ops []StackOp
	EmitVerifyRabinSig(func(op StackOp) { ops = append(ops, op) })

	if len(ops) != len(rabinGolden) {
		t.Fatalf("expected %d opcodes, got %d", len(rabinGolden), len(ops))
	}
	for i, op := range ops {
		want := rabinGolden[i]
		if op.Op != want.op {
			t.Errorf("op %d: expected Op=%q, got %q", i, want.op, op.Op)
		}
		switch want.op {
		case "opcode":
			if op.Code != want.code {
				t.Errorf("op %d: expected Code=%q, got %q", i, want.code, op.Code)
			}
		case "push":
			if op.Value.Kind != "bigint" {
				t.Errorf("op %d: expected push Kind=bigint, got %q", i, op.Value.Kind)
			}
			if op.Value.BigInt == nil || op.Value.BigInt.Cmp(big.NewInt(want.value)) != 0 {
				t.Errorf("op %d: expected push value=%d, got %v", i, want.value, op.Value.BigInt)
			}
		}
	}
}

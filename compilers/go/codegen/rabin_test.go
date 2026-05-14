package codegen

import "testing"

// rabinGolden is the fixed 10-opcode Rabin verification sequence:
// (sig^2 + padding) mod pubKey == SHA256(msg).
var rabinGolden = []string{
	"OP_SWAP",
	"OP_ROT",
	"OP_DUP",
	"OP_MUL",
	"OP_ADD",
	"OP_SWAP",
	"OP_MOD",
	"OP_SWAP",
	"OP_SHA256",
	"OP_EQUAL",
}

// TestEmitVerifyRabinSig_ByteFrozenGolden pins the exact opcode sequence
// emitted by the extracted rabin.go module (GAP-M1).
func TestEmitVerifyRabinSig_ByteFrozenGolden(t *testing.T) {
	var ops []StackOp
	EmitVerifyRabinSig(func(op StackOp) { ops = append(ops, op) })

	if len(ops) != len(rabinGolden) {
		t.Fatalf("expected %d opcodes, got %d", len(rabinGolden), len(ops))
	}
	for i, op := range ops {
		if op.Op != "opcode" {
			t.Errorf("op %d: expected Op=opcode, got %q", i, op.Op)
		}
		if op.Code != rabinGolden[i] {
			t.Errorf("op %d: expected %q, got %q", i, rabinGolden[i], op.Code)
		}
	}
}

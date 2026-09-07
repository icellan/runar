package codegen

import (
	"testing"
)

// The cost model must be a CHECKED MIRROR of the emitter, not a second opinion.
//
// Every optimizer decision downstream — which constants to pool, which comb
// window to keep — is made by comparing SizeOfStackOp totals BEFORE any bytes
// exist. A model that drifts from emit.go by even one byte per push silently
// picks the wrong candidate and reports a saving that is not there. So the gate
// is exact equality against the real emitter over every crypto emitter in the
// tier, if-bodies and all.
func TestCostModelMatchesEmitter(t *testing.T) {
	cases := []struct {
		name string
		emit func(func(StackOp))
	}{
		{"Sha256Compress", EmitSha256Compress},
		{"Sha256Finalize", EmitSha256Finalize},
		{"Blake3Compress", EmitBlake3Compress},
		{"Blake3Hash", EmitBlake3Hash},
		{"EcAdd", ecNoOpts(EmitEcAdd)},
		{"EcMul", ecNoOpts(EmitEcMul)},
		{"EcMulGen", ecNoOpts(EmitEcMulGen)},
		{"EcNegate", ecNoOpts(EmitEcNegate)},
		{"EcOnCurve", ecNoOpts(EmitEcOnCurve)},
		{"EcModReduce", EmitEcModReduce},
		{"EcEncodeCompressed", EmitEcEncodeCompressed},
		{"EcMakePoint", EmitEcMakePoint},
		{"EcPointX", EmitEcPointX},
		{"EcPointY", EmitEcPointY},
		{"P256Add", ecNoOpts(EmitP256Add)},
		{"P256Mul", ecNoOpts(EmitP256Mul)},
		{"P256MulGen", ecNoOpts(EmitP256MulGen)},
		{"VerifyECDSA_P256", ecNoOpts(EmitVerifyECDSA_P256)},
		{"P384Add", ecNoOpts(EmitP384Add)},
		{"P384Mul", ecNoOpts(EmitP384Mul)},
		{"P384MulGen", ecNoOpts(EmitP384MulGen)},
		{"VerifyECDSA_P384", ecNoOpts(EmitVerifyECDSA_P384)},
		{"VerifyWOTS", EmitVerifyWOTS},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ops := gatherOps(tc.emit)
			method := &StackMethod{Name: "t", Ops: ops}
			res, err := EmitMethod(method)
			if err != nil {
				t.Fatalf("%s: emit failed: %v", tc.name, err)
			}
			want := len(res.ScriptHex) / 2
			if got := EstimateScriptBytes(ops); got != want {
				t.Fatalf("%s: cost model says %d bytes, emitter produced %d", tc.name, got, want)
			}
		})
	}
}

// A pick/roll depth operand is a SEPARATE push op the tracker emits just
// before, so charging the depth to the pick would double-count it. Pin that.
func TestCostModelPickRollAreOneByte(t *testing.T) {
	for _, op := range []StackOp{{Op: "pick", Depth: 40}, {Op: "roll", Depth: 40}} {
		if got := SizeOfStackOp(op); got != 1 {
			t.Fatalf("%s: want 1 byte, got %d", op.Op, got)
		}
	}
}

// The emitter writes OP_ELSE only for a NON-EMPTY else arm, so an if with an
// empty else is 3 bytes, not 4. Every conditional add in the ladders and the
// comb has an empty else arm, so a wrong constant here mis-scores tens of
// thousands of branches.
func TestCostModelEmptyElseArmHasNoOpElse(t *testing.T) {
	empty := StackOp{Op: "if", Then: []StackOp{{Op: "dup"}}}
	if got := SizeOfStackOp(empty); got != 3 {
		t.Fatalf("empty else arm: want 3 bytes (OP_IF DUP OP_ENDIF), got %d", got)
	}
	full := StackOp{Op: "if", Then: []StackOp{{Op: "dup"}}, Else: []StackOp{{Op: "drop"}}}
	if got := SizeOfStackOp(full); got != 5 {
		t.Fatalf("non-empty else arm: want 5 bytes, got %d", got)
	}
}

// An unknown mnemonic must fail loudly. Costing it zero is how a codegen typo
// becomes a size report that is quietly wrong.
func TestCostModelRejectsUnknownOpcode(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected a panic for an unknown opcode")
		}
	}()
	SizeOfStackOp(StackOp{Op: "opcode", Code: "OP_NOT_A_REAL_OPCODE"})
}

// ecNoOpts adapts an options-taking EC emitter to the bare
// `func(func(StackOp))` shape the op-count and cost-model tables use. The
// flag-sensitive behaviour is covered separately by
// ec_flag_parity_test.go; these tables are about the DEFAULT output.
func ecNoOpts(f func(func(StackOp), *EcCodegenOptions)) func(func(StackOp)) {
	return func(e func(StackOp)) { f(e, nil) }
}

package codegen

import (
	"math/big"
	"testing"

	"github.com/icellan/runar/compilers/go/ir"
)

// ---------------------------------------------------------------------------
// R-169, the `pow` half — the emitted `pow` silently returned base^32 for any
// larger exponent.
//
// `lowerPow` unrolls exactly 32 conditional multiplies, so it computes
// base^min(exp, 32). Until this guard landed, nothing checked the exponent:
// measured on the real @bsv/sdk Spend interpreter, pow(2,33) and pow(2,40)
// both returned 4294967296 and pow(2,-1) returned 1 — no abort, no
// diagnostic. All seven tiers clamped identically, so cross-tier hex parity
// was green on the wrong answer, while `frontend/constant_fold.go` computed
// the TRUE power for any 0 <= exp <= 256. Inside 33..256 the fold-ON and
// fold-OFF scripts therefore accepted MUTUALLY EXCLUSIVE inputs.
//
// The guard, six bytes per callsite, on the exponent:
//
//	OP_DUP <0> <33> OP_WITHIN OP_VERIFY
//
// The folder declines and the reference interpreter throws on exactly the
// same bound, so all three refuse together.
// ---------------------------------------------------------------------------

// powProgram builds a minimal one-method contract computing pow(a, b) and
// comparing it against a readonly property, so neither operand is constant
// and the folder cannot reach the call.
func powProgram() *ir.ANFProgram {
	assertRef, _ := marshalString("t4")
	return &ir.ANFProgram{
		ContractName: "PowProbe",
		Properties: []ir.ANFProperty{
			{Name: "target", Type: "bigint", Readonly: true},
		},
		Methods: []ir.ANFMethod{
			{
				Name:     "constructor",
				Params:   []ir.ANFParam{{Name: "target", Type: "bigint"}},
				IsPublic: false,
			},
			{
				Name: "verify",
				Params: []ir.ANFParam{
					{Name: "a", Type: "bigint"},
					{Name: "b", Type: "bigint"},
				},
				Body: []ir.ANFBinding{
					{Name: "t0", Value: ir.ANFValue{Kind: "load_param", Name: "a"}},
					{Name: "t1", Value: ir.ANFValue{Kind: "load_param", Name: "b"}},
					{Name: "t2", Value: ir.ANFValue{Kind: "call", Func: "pow", Args: []string{"t0", "t1"}}},
					{Name: "t3", Value: ir.ANFValue{Kind: "load_prop", Name: "target"}},
					{Name: "t4", Value: ir.ANFValue{Kind: "bin_op", Op: "===", Left: "t2", Right: "t3"}},
					{Name: "t5", Value: ir.ANFValue{Kind: "assert", RawValue: assertRef, ValueRef: "t4"}},
				},
				IsPublic: true,
			},
		},
	}
}

func powVerifyOps(t *testing.T) []StackOp {
	t.Helper()
	methods := mustLowerToStackOps(t, powProgram())
	for i := range methods {
		if methods[i].Name == "verify" {
			return methods[i].Ops
		}
	}
	t.Fatal("could not find 'verify' stack method")
	return nil
}

// TestR169_PowGuardsTheExponentDomainBeforeUnrolling pins the guard as an
// ORDERED window sited before the first unrolled round, not as a membership
// test: a guard emitted after the OP_SWAP would be reading the base rather
// than the exponent, and one without OP_VERIFY would leave a boolean on the
// stack instead of aborting.
func TestR169_PowGuardsTheExponentDomainBeforeUnrolling(t *testing.T) {
	ops := powVerifyOps(t)

	within := -1
	for i, op := range ops {
		if op.Op == "opcode" && op.Code == "OP_WITHIN" {
			if within != -1 {
				t.Fatalf("pow must emit exactly one OP_WITHIN, found a second at %d", i)
			}
			within = i
		}
	}
	if within < 3 {
		t.Fatalf("pow must emit an OP_WITHIN exponent guard; got ops %s", opsToString(ops))
	}

	if op := ops[within-3]; op.Op != "opcode" || op.Code != "OP_DUP" {
		t.Errorf("the guard must DUP the exponent, got %v", op)
	}
	if got := pushedInt(t, ops[within-2]); got.Cmp(big.NewInt(0)) != 0 {
		t.Errorf("guard lower bound must be 0, got %s", got)
	}
	// 33, not 32: OP_WITHIN is half-open, so a bound of 32 would reject the
	// largest exponent the unroll can actually compute.
	want := big.NewInt(int64(powExponentLimit) + 1)
	if got := pushedInt(t, ops[within-1]); got.Cmp(want) != 0 {
		t.Errorf("guard upper bound must be powExponentLimit+1 = %s, got %s", want, got)
	}
	if op := ops[within+1]; op.Op != "opcode" || op.Code != "OP_VERIFY" {
		t.Errorf("the domain check must ABORT, not leave a boolean on the stack; got %v", op)
	}

	firstRound := -1
	for i, op := range ops {
		if op.Op == "if" {
			firstRound = i
			break
		}
	}
	if firstRound == -1 {
		t.Fatal("pow emitted no unrolled rounds")
	}
	if within >= firstRound {
		t.Errorf("the exponent guard (op %d) must run before the first round (op %d)", within, firstRound)
	}
}

// TestR169_PowStillUnrollsExactly32Rounds is the control. The guard must not
// have disturbed the body it protects, and the round count is load-bearing —
// it IS the domain the guard enforces, so it is pinned exactly rather than as
// a lower bound.
func TestR169_PowStillUnrollsExactly32Rounds(t *testing.T) {
	ops := powVerifyOps(t)
	rounds := 0
	for _, op := range ops {
		if op.Op == "if" {
			rounds++
		}
	}
	if rounds != powExponentLimit {
		t.Errorf("pow must unroll exactly %d rounds, got %d", powExponentLimit, rounds)
	}
	if rounds != 32 {
		t.Errorf("powExponentLimit moved to %d: the guard bound, the folder bound in "+
			"frontend/constant_fold.go and the reference interpreter must move with it", rounds)
	}
}

// pushedInt returns the integer a push op carries, failing the test otherwise.
func pushedInt(t *testing.T, op StackOp) *big.Int {
	t.Helper()
	if op.Op != "push" {
		t.Fatalf("expected a push op, got %v", op)
	}
	if op.Value.BigInt == nil {
		t.Fatalf("push op does not carry an integer: %v", op)
	}
	return op.Value.BigInt
}

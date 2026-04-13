package codegen

import (
	"math/big"
	"testing"
)

// Differential tests: verify that tracker-mode and flat-mode BN254 Fp2
// emitters produce the same mathematical result on the same inputs.
//
// Both modes implement the same Karatsuba formulas over Fp2 = Fp[u]/(u²+1).
// Flat mode assumes q is at the stack bottom and uses positional pick/roll;
// tracker mode uses named slots with copyToTop / toTop. A bug in either
// mode's stack manipulation would produce a wrong Fp2 result for that mode
// only, and this test catches the divergence.

// runTrackerFp2Mul runs bn254Fp2MulTracker over named inputs a0,a1,b0,b1
// and returns the computed (r0, r1) as bigints by executing the resulting
// script with the go-sdk interpreter.
func runTrackerFp2Mul(t *testing.T, a0, a1, b0, b1, p *big.Int) {
	t.Helper()

	// Tracker mode does not assume q at bottom. Push the operands, then run
	// the bn254Fp2MulTracker helper through a tracker, which will produce
	// [..., r0, r1]. We then EQUALVERIFY against the math result computed
	// in Go.
	emitted := gatherOps(func(emit func(StackOp)) {
		tr := NewBN254Tracker([]string{"a0", "a1", "b0", "b1"}, emit)
		bn254Fp2MulTracker(tr, "a0", "a1", "b0", "b1", "r0", "r1")
		// Bring r1 then r0 to top so the final stack layout is
		// [..., r0, r1] — EQUALVERIFY expects [..., actual, expected].
		tr.toTop("r0")
		tr.toTop("r1")
	})

	r0, r1 := fp2MulMath(a0, a1, b0, b1, p)

	var ops []StackOp
	ops = append(ops, pushBigInt(a0))
	ops = append(ops, pushBigInt(a1))
	ops = append(ops, pushBigInt(b0))
	ops = append(ops, pushBigInt(b1))
	ops = append(ops, emitted...)
	// Stack: [..., r0, r1]
	ops = append(ops, pushBigInt(r1))
	ops = append(ops, opcode("OP_EQUALVERIFY"))
	ops = append(ops, pushBigInt(r0))
	ops = append(ops, opcode("OP_EQUALVERIFY"))
	ops = append(ops, opcode("OP_1"))

	if err := buildAndExecute(t, ops); err != nil {
		t.Fatalf("tracker Fp2Mul: %v", err)
	}
}

// runFlatFp2Mul runs EmitFlatFp2Mul over the same operands (with q at the
// bottom per the flat-mode calling convention).
func runFlatFp2Mul(t *testing.T, a0, a1, b0, b1, p *big.Int) {
	t.Helper()
	flatOps := gatherOps(EmitFlatFp2Mul)
	r0, r1 := fp2MulMath(a0, a1, b0, b1, p)

	var ops []StackOp
	ops = append(ops, pushBigInt(p))
	ops = append(ops, pushBigInt(a0))
	ops = append(ops, pushBigInt(a1))
	ops = append(ops, pushBigInt(b0))
	ops = append(ops, pushBigInt(b1))
	ops = append(ops, flatOps...)
	// Stack: [q, r0, r1]
	ops = append(ops, pushBigInt(r1))
	ops = append(ops, opcode("OP_EQUALVERIFY"))
	ops = append(ops, pushBigInt(r0))
	ops = append(ops, opcode("OP_EQUALVERIFY"))
	ops = append(ops, opcode("OP_DROP")) // drop q
	ops = append(ops, opcode("OP_1"))

	if err := buildAndExecute(t, ops); err != nil {
		t.Fatalf("flat Fp2Mul: %v", err)
	}
}

// runTrackerFp2Sqr / runFlatFp2Sqr mirror the above for squaring.
func runTrackerFp2Sqr(t *testing.T, a0, a1, p *big.Int) {
	t.Helper()
	emitted := gatherOps(func(emit func(StackOp)) {
		tr := NewBN254Tracker([]string{"a0", "a1"}, emit)
		bn254Fp2Sqr(tr, "a0", "a1", "r0", "r1")
		tr.toTop("r0")
		tr.toTop("r1")
	})
	r0, r1 := fp2SqrMath(a0, a1, p)

	var ops []StackOp
	ops = append(ops, pushBigInt(a0))
	ops = append(ops, pushBigInt(a1))
	ops = append(ops, emitted...)
	ops = append(ops, pushBigInt(r1))
	ops = append(ops, opcode("OP_EQUALVERIFY"))
	ops = append(ops, pushBigInt(r0))
	ops = append(ops, opcode("OP_EQUALVERIFY"))
	ops = append(ops, opcode("OP_1"))

	if err := buildAndExecute(t, ops); err != nil {
		t.Fatalf("tracker Fp2Sqr: %v", err)
	}
}

func runFlatFp2Sqr(t *testing.T, a0, a1, p *big.Int) {
	t.Helper()
	flatOps := gatherOps(EmitFlatFp2Sqr)
	r0, r1 := fp2SqrMath(a0, a1, p)

	var ops []StackOp
	ops = append(ops, pushBigInt(p))
	ops = append(ops, pushBigInt(a0))
	ops = append(ops, pushBigInt(a1))
	ops = append(ops, flatOps...)
	ops = append(ops, pushBigInt(r1))
	ops = append(ops, opcode("OP_EQUALVERIFY"))
	ops = append(ops, pushBigInt(r0))
	ops = append(ops, opcode("OP_EQUALVERIFY"))
	ops = append(ops, opcode("OP_DROP"))
	ops = append(ops, opcode("OP_1"))

	if err := buildAndExecute(t, ops); err != nil {
		t.Fatalf("flat Fp2Sqr: %v", err)
	}
}

// fp2MulMath computes the reference Fp2 product (a0+a1·u)*(b0+b1·u) mod p.
func fp2MulMath(a0, a1, b0, b1, p *big.Int) (*big.Int, *big.Int) {
	r0 := new(big.Int).Sub(new(big.Int).Mul(a0, b0), new(big.Int).Mul(a1, b1))
	r0.Mod(r0, p)
	if r0.Sign() < 0 {
		r0.Add(r0, p)
	}
	r1 := new(big.Int).Add(new(big.Int).Mul(a0, b1), new(big.Int).Mul(a1, b0))
	r1.Mod(r1, p)
	return r0, r1
}

// fp2SqrMath computes (a0+a1·u)² = (a0²-a1²) + 2·a0·a1·u mod p.
func fp2SqrMath(a0, a1, p *big.Int) (*big.Int, *big.Int) {
	r0 := new(big.Int).Sub(new(big.Int).Mul(a0, a0), new(big.Int).Mul(a1, a1))
	r0.Mod(r0, p)
	if r0.Sign() < 0 {
		r0.Add(r0, p)
	}
	r1 := new(big.Int).Mul(a0, a1)
	r1.Lsh(r1, 1)
	r1.Mod(r1, p)
	return r0, r1
}

// TestBN254Fp2_TrackerVsFlat_Mul asserts that bn254Fp2MulTracker and
// EmitFlatFp2Mul agree on a range of inputs: both small values, large
// operands close to p, and mixed-signs operands that exercise the negative
// r0 branch.
func TestBN254Fp2_TrackerVsFlat_Mul(t *testing.T) {
	p, _ := new(big.Int).SetString(
		"21888242871839275222246405745257275088696311157297823662689037894645226208583", 10)

	cases := []struct {
		name           string
		a0, a1, b0, b1 *big.Int
	}{
		{"small", big.NewInt(3), big.NewInt(4), big.NewInt(5), big.NewInt(7)},
		{
			"large_positive",
			mustParseBig("12345678901234567890123456789012345678901234567890123456789012345678901234567"),
			mustParseBig("98765432109876543210987654321098765432109876543210987654321098765432109876543"),
			mustParseBig("11111111111111111111111111111111111111111111111111111111111111111111111111111"),
			mustParseBig("22222222222222222222222222222222222222222222222222222222222222222222222222222"),
		},
		{
			"negative_r0",
			big.NewInt(2), big.NewInt(10), big.NewInt(3), big.NewInt(20),
		},
		{
			"one_operand_zero",
			big.NewInt(0), big.NewInt(7), big.NewInt(5), big.NewInt(0),
		},
		{
			"near_p",
			new(big.Int).Sub(p, big.NewInt(1)),
			new(big.Int).Sub(p, big.NewInt(2)),
			new(big.Int).Sub(p, big.NewInt(3)),
			new(big.Int).Sub(p, big.NewInt(4)),
		},
	}

	for _, tc := range cases {
		tc := tc
		a0 := new(big.Int).Mod(tc.a0, p)
		a1 := new(big.Int).Mod(tc.a1, p)
		b0 := new(big.Int).Mod(tc.b0, p)
		b1 := new(big.Int).Mod(tc.b1, p)

		t.Run(tc.name+"_tracker", func(t *testing.T) {
			runTrackerFp2Mul(t, a0, a1, b0, b1, p)
		})
		t.Run(tc.name+"_flat", func(t *testing.T) {
			runFlatFp2Mul(t, a0, a1, b0, b1, p)
		})
	}
}

// TestBN254Fp2_TrackerVsFlat_Sqr is the squaring counterpart to
// TestBN254Fp2_TrackerVsFlat_Mul.
func TestBN254Fp2_TrackerVsFlat_Sqr(t *testing.T) {
	p, _ := new(big.Int).SetString(
		"21888242871839275222246405745257275088696311157297823662689037894645226208583", 10)

	cases := []struct {
		name   string
		a0, a1 *big.Int
	}{
		{"small", big.NewInt(3), big.NewInt(4)},
		{
			"large",
			mustParseBig("12345678901234567890123456789012345678901234567890123456789012345678901234567"),
			mustParseBig("98765432109876543210987654321098765432109876543210987654321098765432109876543"),
		},
		{"zero_real", big.NewInt(0), big.NewInt(7)},
		{"zero_imag", big.NewInt(5), big.NewInt(0)},
		{
			"near_p",
			new(big.Int).Sub(p, big.NewInt(1)),
			new(big.Int).Sub(p, big.NewInt(2)),
		},
	}

	for _, tc := range cases {
		tc := tc
		a0 := new(big.Int).Mod(tc.a0, p)
		a1 := new(big.Int).Mod(tc.a1, p)

		t.Run(tc.name+"_tracker", func(t *testing.T) {
			runTrackerFp2Sqr(t, a0, a1, p)
		})
		t.Run(tc.name+"_flat", func(t *testing.T) {
			runFlatFp2Sqr(t, a0, a1, p)
		})
	}
}

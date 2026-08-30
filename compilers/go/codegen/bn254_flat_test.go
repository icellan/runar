package codegen

import (
	"math/big"
	"testing"
)

// ---------------------------------------------------------------------------
// Flat Fp2 Multiplication tests
// ---------------------------------------------------------------------------

func TestFlatFp2Mul_Small_Script(t *testing.T) {
	p, _ := new(big.Int).SetString("21888242871839275222246405745257275088696311157297823662689037894645226208583", 10)

	// a = (3, 4), b = (5, 7)
	// (3 + 4u)*(5 + 7u) = (15 - 28) + (21 + 20)u = -13 + 41u
	a0 := big.NewInt(3)
	a1 := big.NewInt(4)
	b0 := big.NewInt(5)
	b1 := big.NewInt(7)

	r0 := new(big.Int).Sub(new(big.Int).Mul(a0, b0), new(big.Int).Mul(a1, b1))
	r0.Mod(r0, p)
	if r0.Sign() < 0 {
		r0.Add(r0, p)
	}
	r1 := new(big.Int).Add(new(big.Int).Mul(a0, b1), new(big.Int).Mul(a1, b0))
	r1.Mod(r1, p)

	flatOps := gatherOps(EmitFlatFp2Mul)

	var ops []StackOp
	// Push q at bottom, then a0, a1, b0, b1
	ops = append(ops, pushBigInt(p))
	ops = append(ops, pushBigInt(a0))
	ops = append(ops, pushBigInt(a1))
	ops = append(ops, pushBigInt(b0))
	ops = append(ops, pushBigInt(b1))
	ops = append(ops, flatOps...)
	// Stack should be: [q, r0, r1]
	// Verify r1
	ops = append(ops, pushBigInt(r1))
	ops = append(ops, opcode("OP_EQUALVERIFY"))
	// Verify r0
	ops = append(ops, pushBigInt(r0))
	ops = append(ops, opcode("OP_EQUALVERIFY"))
	// Drop q, push 1
	ops = append(ops, opcode("OP_DROP"))
	ops = append(ops, opcode("OP_1"))

	if err := buildAndExecute(t, ops); err != nil {
		t.Errorf("flat Fp2 mul (small) failed: %v", err)
	}
}

func TestFlatFp2Mul_Large_Script(t *testing.T) {
	p, _ := new(big.Int).SetString("21888242871839275222246405745257275088696311157297823662689037894645226208583", 10)

	a0, _ := new(big.Int).SetString("12345678901234567890123456789012345678901234567890123456789012345678901234567", 10)
	a0.Mod(a0, p)
	a1, _ := new(big.Int).SetString("98765432109876543210987654321098765432109876543210987654321098765432109876543", 10)
	a1.Mod(a1, p)
	b0, _ := new(big.Int).SetString("11111111111111111111111111111111111111111111111111111111111111111111111111111", 10)
	b0.Mod(b0, p)
	b1, _ := new(big.Int).SetString("22222222222222222222222222222222222222222222222222222222222222222222222222222", 10)
	b1.Mod(b1, p)

	// Fp2 mul: r0 = a0*b0 - a1*b1, r1 = a0*b1 + a1*b0 (all mod p)
	r0 := new(big.Int).Sub(new(big.Int).Mul(a0, b0), new(big.Int).Mul(a1, b1))
	r0.Mod(r0, p)
	r1 := new(big.Int).Add(new(big.Int).Mul(a0, b1), new(big.Int).Mul(a1, b0))
	r1.Mod(r1, p)

	flatOps := gatherOps(EmitFlatFp2Mul)

	var ops []StackOp
	ops = append(ops, pushBigInt(p))
	ops = append(ops, pushBigInt(a0))
	ops = append(ops, pushBigInt(a1))
	ops = append(ops, pushBigInt(b0))
	ops = append(ops, pushBigInt(b1))
	ops = append(ops, flatOps...)
	ops = append(ops, pushBigInt(r1))
	ops = append(ops, opcode("OP_EQUALVERIFY"))
	ops = append(ops, pushBigInt(r0))
	ops = append(ops, opcode("OP_EQUALVERIFY"))
	ops = append(ops, opcode("OP_DROP")) // drop q
	ops = append(ops, opcode("OP_1"))

	if err := buildAndExecute(t, ops); err != nil {
		t.Errorf("flat Fp2 mul (large) failed: %v", err)
	}
}

func TestFlatFp2Mul_NegativeResult_Script(t *testing.T) {
	p, _ := new(big.Int).SetString("21888242871839275222246405745257275088696311157297823662689037894645226208583", 10)

	// Choose values where a0*b0 < a1*b1 so r0 is negative before mod
	a0 := big.NewInt(2)
	a1 := big.NewInt(10)
	b0 := big.NewInt(3)
	b1 := big.NewInt(7)
	// r0 = 2*3 - 10*7 = 6 - 70 = -64 mod p = p - 64
	// r1 = 2*7 + 10*3 = 14 + 30 = 44

	r0 := new(big.Int).Sub(new(big.Int).Mul(a0, b0), new(big.Int).Mul(a1, b1))
	r0.Mod(r0, p)
	r1 := new(big.Int).Add(new(big.Int).Mul(a0, b1), new(big.Int).Mul(a1, b0))
	r1.Mod(r1, p)

	flatOps := gatherOps(EmitFlatFp2Mul)

	var ops []StackOp
	ops = append(ops, pushBigInt(p))
	ops = append(ops, pushBigInt(a0))
	ops = append(ops, pushBigInt(a1))
	ops = append(ops, pushBigInt(b0))
	ops = append(ops, pushBigInt(b1))
	ops = append(ops, flatOps...)
	ops = append(ops, pushBigInt(r1))
	ops = append(ops, opcode("OP_EQUALVERIFY"))
	ops = append(ops, pushBigInt(r0))
	ops = append(ops, opcode("OP_EQUALVERIFY"))
	ops = append(ops, opcode("OP_DROP"))
	ops = append(ops, opcode("OP_1"))

	if err := buildAndExecute(t, ops); err != nil {
		t.Errorf("flat Fp2 mul (negative r0) failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Flat Fp2 Addition test
// ---------------------------------------------------------------------------

func TestFlatFp2Add_Script(t *testing.T) {
	p, _ := new(big.Int).SetString("21888242871839275222246405745257275088696311157297823662689037894645226208583", 10)

	a0, _ := new(big.Int).SetString("20000000000000000000000000000000000000000000000000000000000000000000000000000", 10)
	a0.Mod(a0, p)
	a1, _ := new(big.Int).SetString("15000000000000000000000000000000000000000000000000000000000000000000000000000", 10)
	a1.Mod(a1, p)
	b0, _ := new(big.Int).SetString("18000000000000000000000000000000000000000000000000000000000000000000000000000", 10)
	b0.Mod(b0, p)
	b1, _ := new(big.Int).SetString("12000000000000000000000000000000000000000000000000000000000000000000000000000", 10)
	b1.Mod(b1, p)

	r0 := new(big.Int).Add(a0, b0)
	r0.Mod(r0, p)
	r1 := new(big.Int).Add(a1, b1)
	r1.Mod(r1, p)

	flatOps := gatherOps(EmitFlatFp2Add)

	var ops []StackOp
	ops = append(ops, pushBigInt(p))
	ops = append(ops, pushBigInt(a0))
	ops = append(ops, pushBigInt(a1))
	ops = append(ops, pushBigInt(b0))
	ops = append(ops, pushBigInt(b1))
	ops = append(ops, flatOps...)
	ops = append(ops, pushBigInt(r1))
	ops = append(ops, opcode("OP_EQUALVERIFY"))
	ops = append(ops, pushBigInt(r0))
	ops = append(ops, opcode("OP_EQUALVERIFY"))
	ops = append(ops, opcode("OP_DROP"))
	ops = append(ops, opcode("OP_1"))

	if err := buildAndExecute(t, ops); err != nil {
		t.Errorf("flat Fp2 add failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Flat Fp2 Subtraction test
// ---------------------------------------------------------------------------

func TestFlatFp2Sub_Script(t *testing.T) {
	p, _ := new(big.Int).SetString("21888242871839275222246405745257275088696311157297823662689037894645226208583", 10)

	a0 := big.NewInt(100)
	a1 := big.NewInt(200)
	b0 := big.NewInt(300) // b0 > a0 -> negative difference
	b1 := big.NewInt(50)

	r0 := new(big.Int).Sub(a0, b0)
	r0.Mod(r0, p) // wraps around
	r1 := new(big.Int).Sub(a1, b1)
	r1.Mod(r1, p)

	flatOps := gatherOps(EmitFlatFp2Sub)

	var ops []StackOp
	ops = append(ops, pushBigInt(p))
	ops = append(ops, pushBigInt(a0))
	ops = append(ops, pushBigInt(a1))
	ops = append(ops, pushBigInt(b0))
	ops = append(ops, pushBigInt(b1))
	ops = append(ops, flatOps...)
	ops = append(ops, pushBigInt(r1))
	ops = append(ops, opcode("OP_EQUALVERIFY"))
	ops = append(ops, pushBigInt(r0))
	ops = append(ops, opcode("OP_EQUALVERIFY"))
	ops = append(ops, opcode("OP_DROP"))
	ops = append(ops, opcode("OP_1"))

	if err := buildAndExecute(t, ops); err != nil {
		t.Errorf("flat Fp2 sub failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Flat Fp2 Squaring test
// ---------------------------------------------------------------------------

func TestFlatFp2Sqr_Script(t *testing.T) {
	p, _ := new(big.Int).SetString("21888242871839275222246405745257275088696311157297823662689037894645226208583", 10)

	a0 := big.NewInt(7)
	a1 := big.NewInt(11)

	// (7 + 11u)^2 = (49 - 121) + 2*77*u = -72 + 154u
	r0 := new(big.Int).Sub(new(big.Int).Mul(a0, a0), new(big.Int).Mul(a1, a1))
	r0.Mod(r0, p)
	r1 := new(big.Int).Mul(big.NewInt(2), new(big.Int).Mul(a0, a1))
	r1.Mod(r1, p)

	flatOps := gatherOps(EmitFlatFp2Sqr)

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
		t.Errorf("flat Fp2 sqr failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Flat Fp2 MulByNonResidue test
// ---------------------------------------------------------------------------

func TestFlatFp2MulByNonResidue_Script(t *testing.T) {
	p, _ := new(big.Int).SetString("21888242871839275222246405745257275088696311157297823662689037894645226208583", 10)

	a0 := big.NewInt(5)
	a1 := big.NewInt(3)

	// (5 + 3u)(9 + u) = (45 - 3) + (5 + 27)u = 42 + 32u
	r0 := new(big.Int).Sub(
		new(big.Int).Mul(big.NewInt(9), a0),
		a1,
	)
	r0.Mod(r0, p)
	r1 := new(big.Int).Add(
		a0,
		new(big.Int).Mul(big.NewInt(9), a1),
	)
	r1.Mod(r1, p)

	flatOps := gatherOps(EmitFlatFp2MulByNonResidue)

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
		t.Errorf("flat Fp2 mulByNonResidue failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Flat Fp2 Multiplication — analytically verifiable test vectors
//
// These tests use hardcoded expected values that can be verified by hand,
// independent of the Fp2 multiplication formula, to catch systematic formula
// errors (e.g., wrong sign on cross-terms).
// ---------------------------------------------------------------------------

func TestFlatFp2Mul_Analytical_Script(t *testing.T) {
	p, _ := new(big.Int).SetString("21888242871839275222246405745257275088696311157297823662689037894645226208583", 10)

	// Analytical test vectors where expected values are trivially derivable:
	//
	// Fp2 = Fp[u]/(u² + 1), so u² = -1.
	//
	// (a0 + a1*u) * (b0 + b1*u) = (a0*b0 - a1*b1) + (a0*b1 + a1*b0)*u
	tests := []struct {
		name         string
		a0, a1       *big.Int
		b0, b1       *big.Int
		expR0, expR1 *big.Int
	}{
		{
			// (0 + 0u) * (5 + 3u) = 0 + 0u
			name: "zero_times_any",
			a0: big.NewInt(0), a1: big.NewInt(0),
			b0: big.NewInt(5), b1: big.NewInt(3),
			expR0: big.NewInt(0), expR1: big.NewInt(0),
		},
		{
			// (1 + 0u) * (7 + 11u) = 7 + 11u  (multiplicative identity)
			name: "identity",
			a0: big.NewInt(1), a1: big.NewInt(0),
			b0: big.NewInt(7), b1: big.NewInt(11),
			expR0: big.NewInt(7), expR1: big.NewInt(11),
		},
		{
			// (0 + 1u) * (0 + 1u) = u² = -1 mod p = p-1
			name: "i_squared_equals_minus_one",
			a0: big.NewInt(0), a1: big.NewInt(1),
			b0: big.NewInt(0), b1: big.NewInt(1),
			expR0: new(big.Int).Sub(p, big.NewInt(1)), expR1: big.NewInt(0),
		},
		{
			// (1 + 1u) * (1 - 1u) = 1*1 - 1*(-1) + (1*(-1) + 1*1)u = 2 + 0u
			// (difference of squares: |1+u|² = 1 - u² = 1 - (-1) = 2)
			name: "conjugate_product",
			a0: big.NewInt(1), a1: big.NewInt(1),
			b0: big.NewInt(1), b1: new(big.Int).Sub(p, big.NewInt(1)), // -1 mod p
			expR0: big.NewInt(2), expR1: big.NewInt(0),
		},
		{
			// (1 + 1u) * (1 + 1u) = (1 - 1) + (1 + 1)u = 0 + 2u
			name: "one_plus_i_squared",
			a0: big.NewInt(1), a1: big.NewInt(1),
			b0: big.NewInt(1), b1: big.NewInt(1),
			expR0: big.NewInt(0), expR1: big.NewInt(2),
		},
		{
			// (3 + 0u) * (0 + 5u) = 0 + 15u  (real * pure imaginary)
			name: "real_times_imaginary",
			a0: big.NewInt(3), a1: big.NewInt(0),
			b0: big.NewInt(0), b1: big.NewInt(5),
			expR0: big.NewInt(0), expR1: big.NewInt(15),
		},
	}

	flatOps := gatherOps(EmitFlatFp2Mul)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ops []StackOp
			ops = append(ops, pushBigInt(p))
			ops = append(ops, pushBigInt(tt.a0))
			ops = append(ops, pushBigInt(tt.a1))
			ops = append(ops, pushBigInt(tt.b0))
			ops = append(ops, pushBigInt(tt.b1))
			ops = append(ops, flatOps...)
			ops = append(ops, pushBigInt(tt.expR1))
			ops = append(ops, opcode("OP_EQUALVERIFY"))
			ops = append(ops, pushBigInt(tt.expR0))
			ops = append(ops, opcode("OP_EQUALVERIFY"))
			ops = append(ops, opcode("OP_DROP"))
			ops = append(ops, opcode("OP_1"))

			if err := buildAndExecute(t, ops); err != nil {
				t.Errorf("analytical Fp2 mul (%s) failed: %v", tt.name, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Flat Fp2 negative tests — wrong results MUST cause script failure
// ---------------------------------------------------------------------------

func TestFlatFp2Mul_WrongResult_Script(t *testing.T) {
	p, _ := new(big.Int).SetString("21888242871839275222246405745257275088696311157297823662689037894645226208583", 10)

	a0 := big.NewInt(3)
	a1 := big.NewInt(5)
	b0 := big.NewInt(7)
	b1 := big.NewInt(11)

	// Compute correct result
	r0 := new(big.Int).Sub(new(big.Int).Mul(a0, b0), new(big.Int).Mul(a1, b1))
	r0.Mod(r0, p)
	r1 := new(big.Int).Add(new(big.Int).Mul(a0, b1), new(big.Int).Mul(a1, b0))
	r1.Mod(r1, p)

	// Swap r0 and r1 (wrong order) — the script should reject this
	flatOps := gatherOps(EmitFlatFp2Mul)

	var ops []StackOp
	ops = append(ops, pushBigInt(p))
	ops = append(ops, pushBigInt(a0))
	ops = append(ops, pushBigInt(a1))
	ops = append(ops, pushBigInt(b0))
	ops = append(ops, pushBigInt(b1))
	ops = append(ops, flatOps...)
	// Wrong: check r0 where r1 should be (swapped)
	ops = append(ops, pushBigInt(r0))
	ops = append(ops, opcode("OP_EQUALVERIFY"))
	ops = append(ops, pushBigInt(r1))
	ops = append(ops, opcode("OP_EQUALVERIFY"))
	ops = append(ops, opcode("OP_DROP"))
	ops = append(ops, opcode("OP_1"))

	if err := buildAndExecute(t, ops); err == nil {
		t.Error("expected script to FAIL with swapped r0/r1 (wrong result), but it succeeded")
	}
}

func TestFlatFp2Add_WrongResult_Script(t *testing.T) {
	p, _ := new(big.Int).SetString("21888242871839275222246405745257275088696311157297823662689037894645226208583", 10)

	a0 := big.NewInt(100)
	a1 := big.NewInt(200)
	b0 := big.NewInt(300)
	b1 := big.NewInt(400)

	// Correct: r0 = 400, r1 = 600
	// Push wrong r1 = 601
	flatOps := gatherOps(EmitFlatFp2Add)

	var ops []StackOp
	ops = append(ops, pushBigInt(p))
	ops = append(ops, pushBigInt(a0))
	ops = append(ops, pushBigInt(a1))
	ops = append(ops, pushBigInt(b0))
	ops = append(ops, pushBigInt(b1))
	ops = append(ops, flatOps...)
	ops = append(ops, pushBigInt(big.NewInt(601))) // wrong r1
	ops = append(ops, opcode("OP_EQUALVERIFY"))
	ops = append(ops, pushBigInt(big.NewInt(400)))
	ops = append(ops, opcode("OP_EQUALVERIFY"))
	ops = append(ops, opcode("OP_DROP"))
	ops = append(ops, opcode("OP_1"))

	if err := buildAndExecute(t, ops); err == nil {
		t.Error("expected script to FAIL with wrong Fp2 add result, but it succeeded")
	}
}

func TestFlatFp2Sqr_WrongResult_Script(t *testing.T) {
	p, _ := new(big.Int).SetString("21888242871839275222246405745257275088696311157297823662689037894645226208583", 10)

	a0 := big.NewInt(7)
	a1 := big.NewInt(11)

	// Correct: r0 = (49 - 121) mod p = p - 72, r1 = 2*77 = 154
	// Push wrong r0 = 0
	flatOps := gatherOps(EmitFlatFp2Sqr)

	var ops []StackOp
	ops = append(ops, pushBigInt(p))
	ops = append(ops, pushBigInt(a0))
	ops = append(ops, pushBigInt(a1))
	ops = append(ops, flatOps...)
	ops = append(ops, pushBigInt(big.NewInt(154))) // r1 correct
	ops = append(ops, opcode("OP_EQUALVERIFY"))
	ops = append(ops, pushBigInt(big.NewInt(0))) // r0 wrong (should be p-72)
	ops = append(ops, opcode("OP_EQUALVERIFY"))
	ops = append(ops, opcode("OP_DROP"))
	ops = append(ops, opcode("OP_1"))

	if err := buildAndExecute(t, ops); err == nil {
		t.Error("expected script to FAIL with wrong Fp2 sqr result, but it succeeded")
	}
}

// ---------------------------------------------------------------------------
// Opcode count comparison: flat vs tracker
// ---------------------------------------------------------------------------

func TestFlatFp2Mul_OpCount(t *testing.T) {
	flatOps := gatherOps(EmitFlatFp2Mul)
	t.Logf("Flat Fp2 mul: %d StackOps", len(flatOps))

	// Compare with tracker-based (without qAtBottom, so it uses the old path)
	trackerOps := gatherOps(func(emit func(StackOp)) {
		tr := NewBN254Tracker([]string{"a0", "a1", "b0", "b1"}, emit)
		tr.PushPrimeCache()
		bn254Fp2Mul(tr, "a0", "a1", "b0", "b1", "r0", "r1")
		tr.PopPrimeCache()
	})
	t.Logf("Tracker (alt-stack) Fp2 mul: %d StackOps", len(trackerOps))

	// Flat should be significantly fewer ops than the alt-stack tracker path
	if len(flatOps) >= len(trackerOps) {
		t.Errorf("flat Fp2 mul (%d ops) is not fewer than tracker (%d ops)", len(flatOps), len(trackerOps))
	}
}

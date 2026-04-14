package codegen

import (
	"math/big"
	"testing"
)

// Script-runner tests for the generic (non-witness-assisted) BN254 on-chain
// primitives: EmitBN254G1Add, EmitBN254G1ScalarMul, EmitBN254G1Negate.
//
// Context: the bsv-evm team reported (RUNAR-BN254-GENERIC-BUG.md) that these
// primitives had never been exercised through the script interpreter, and that
// their Mode 2 rollup Groth16 contract fails at OP_VERIFY on regtest even
// though the off-chain pairing equation holds for the same inputs. The
// witness-assisted path (EmitGroth16VerifierWitnessAssisted) is thoroughly
// tested and works, but the generic primitives used by Mode 2 had zero
// script-runner coverage.
//
// These tests isolate each generic primitive against known BN254 test vectors
// (G, 2G, 3G, -G) derived from the curve y^2 = x^3 + 3 with generator (1, 2).

// bn254PackPoint encodes (x, y) as the 64-byte BN254 Point format used on
// the Bitcoin Script stack: x (32 bytes big-endian) || y (32 bytes big-endian).
func bn254PackPoint(x, y *big.Int) []byte {
	buf := make([]byte, 64)
	xb := x.Bytes()
	yb := y.Bytes()
	copy(buf[32-len(xb):32], xb)
	copy(buf[64-len(yb):64], yb)
	return buf
}

// pushPoint creates a push StackOp for a 64-byte BN254 Point.
func pushPoint(x, y *big.Int) StackOp {
	return StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: bn254PackPoint(x, y)}}
}

// bn254ComputeDoubleG returns 2G for the BN254 generator G = (1, 2).
func bn254ComputeDoubleG(t *testing.T) (*big.Int, *big.Int) {
	t.Helper()
	p := new(big.Int).Set(bn254FieldP)
	x1 := big.NewInt(1)
	y1 := big.NewInt(2)

	// lambda_dbl = 3*x1^2 / (2*y1) mod p
	lam := new(big.Int).Mul(big.NewInt(3), new(big.Int).Mul(x1, x1))
	denom := new(big.Int).Mul(big.NewInt(2), y1)
	denomInv := new(big.Int).Exp(denom, new(big.Int).Sub(p, big.NewInt(2)), p)
	lam.Mul(lam, denomInv)
	lam.Mod(lam, p)

	// x2 = lambda^2 - 2*x1 mod p
	x2 := new(big.Int).Mul(lam, lam)
	x2.Sub(x2, new(big.Int).Mul(big.NewInt(2), x1))
	x2.Mod(x2, p)
	if x2.Sign() < 0 {
		x2.Add(x2, p)
	}

	// y2 = lambda*(x1 - x2) - y1 mod p
	y2 := new(big.Int).Sub(x1, x2)
	y2.Mul(y2, lam)
	y2.Sub(y2, y1)
	y2.Mod(y2, p)
	if y2.Sign() < 0 {
		y2.Add(y2, p)
	}

	return x2, y2
}

// bn254ComputeAddG_2G returns 3G = G + 2G using the standard affine addition
// formula, against which we check the script-generated result.
func bn254ComputeAddG_2G(t *testing.T) (*big.Int, *big.Int) {
	t.Helper()
	p := new(big.Int).Set(bn254FieldP)
	x1 := big.NewInt(1)
	y1 := big.NewInt(2)
	x2, y2 := bn254ComputeDoubleG(t)

	// lambda = (y2 - y1) / (x2 - x1) mod p
	num := new(big.Int).Sub(y2, y1)
	num.Mod(num, p)
	if num.Sign() < 0 {
		num.Add(num, p)
	}
	den := new(big.Int).Sub(x2, x1)
	den.Mod(den, p)
	if den.Sign() < 0 {
		den.Add(den, p)
	}
	denInv := new(big.Int).Exp(den, new(big.Int).Sub(p, big.NewInt(2)), p)
	lam := new(big.Int).Mul(num, denInv)
	lam.Mod(lam, p)

	// x3 = lambda^2 - x1 - x2 mod p
	x3 := new(big.Int).Mul(lam, lam)
	x3.Sub(x3, x1)
	x3.Sub(x3, x2)
	x3.Mod(x3, p)
	if x3.Sign() < 0 {
		x3.Add(x3, p)
	}

	// y3 = lambda*(x1 - x3) - y1 mod p
	y3 := new(big.Int).Sub(x1, x3)
	y3.Mul(y3, lam)
	y3.Sub(y3, y1)
	y3.Mod(y3, p)
	if y3.Sign() < 0 {
		y3.Add(y3, p)
	}
	return x3, y3
}

// TestBN254G1Negate_Script verifies that EmitBN254G1Negate produces (x, p-y)
// for the generator G = (1, 2). This is the simplest of the generic primitives.
func TestBN254G1Negate_Script(t *testing.T) {
	p := new(big.Int).Set(bn254FieldP)
	gx := big.NewInt(1)
	gy := big.NewInt(2)
	negY := new(big.Int).Sub(p, gy)

	negateOps := gatherOps(EmitBN254G1Negate)

	var ops []StackOp
	// Push G
	ops = append(ops, pushPoint(gx, gy))
	// Negate
	ops = append(ops, negateOps...)
	// Expected: -G = (1, p-2)
	ops = append(ops, pushPoint(gx, negY))
	ops = append(ops, opcode("OP_EQUALVERIFY"))
	ops = append(ops, opcode("OP_1"))

	if err := buildAndExecute(t, ops); err != nil {
		t.Fatalf("EmitBN254G1Negate(G) did not produce (1, p-2): %v", err)
	}
}

// TestBN254G1Add_Script verifies that EmitBN254G1Add computes G + 2G = 3G for
// the BN254 generator. This exercises bn254G1AffineAdd through the script VM
// for the first time.
//
// Also covers G + G = 2G (the doubling case). The original chord formula
//   s = (qy - py) / (qx - px)
// divides by zero when P == Q; the unified slope formula
//   s = (px^2 + px*qx + qx^2) / (py + qy)
// handles both addition and doubling on y^2 = x^3 + b.
func TestBN254G1Add_Script(t *testing.T) {
	gx := big.NewInt(1)
	gy := big.NewInt(2)
	x2, y2 := bn254ComputeDoubleG(t)
	x3, y3 := bn254ComputeAddG_2G(t)

	cases := []struct {
		name                     string
		ax, ay, bx, by, xR, yR *big.Int
	}{
		{"G+2G=3G", gx, gy, x2, y2, x3, y3},
		{"G+G=2G", gx, gy, gx, gy, x2, y2},
		{"2G+G=3G", x2, y2, gx, gy, x3, y3},
		{"2G+2G=4G", x2, y2, x2, y2, nil, nil}, // expected filled in below
	}
	// Compute 4G reference for the 2G+2G case.
	x4, y4 := bn254ComputeKG(t, 4)
	cases[3].xR, cases[3].yR = x4, y4

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			addOps := gatherOps(EmitBN254G1Add)
			var ops []StackOp
			ops = append(ops, pushPoint(tc.ax, tc.ay))
			ops = append(ops, pushPoint(tc.bx, tc.by))
			ops = append(ops, addOps...)
			ops = append(ops, pushPoint(tc.xR, tc.yR))
			ops = append(ops, opcode("OP_EQUALVERIFY"))
			ops = append(ops, opcode("OP_1"))

			if err := buildAndExecute(t, ops); err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
		})
	}
}

// bn254ComputeKG computes k*G by straightforward repeated affine addition,
// used as a reference for script-level scalar mul tests. For small k this is
// obviously correct; for larger k we still rely on the same affine formulas
// the bug-free cases confirm.
func bn254ComputeKG(t *testing.T, k int) (*big.Int, *big.Int) {
	t.Helper()
	if k < 1 {
		t.Fatalf("bn254ComputeKG: k must be >= 1, got %d", k)
	}
	p := new(big.Int).Set(bn254FieldP)
	// Start with G
	x := big.NewInt(1)
	y := big.NewInt(2)
	// Double-and-add from MSB to LSB of k.
	bits := 0
	for tmp := k; tmp > 0; tmp >>= 1 {
		bits++
	}
	// Start from the bit just below the MSB (MSB already represented by P).
	cx := new(big.Int).Set(x)
	cy := new(big.Int).Set(y)
	for i := bits - 2; i >= 0; i-- {
		// Double (cx, cy)
		lam := new(big.Int).Mul(big.NewInt(3), new(big.Int).Mul(cx, cx))
		denom := new(big.Int).Mul(big.NewInt(2), cy)
		denomInv := new(big.Int).Exp(denom, new(big.Int).Sub(p, big.NewInt(2)), p)
		lam.Mul(lam, denomInv)
		lam.Mod(lam, p)
		nx := new(big.Int).Mul(lam, lam)
		nx.Sub(nx, new(big.Int).Mul(big.NewInt(2), cx))
		nx.Mod(nx, p)
		if nx.Sign() < 0 {
			nx.Add(nx, p)
		}
		ny := new(big.Int).Sub(cx, nx)
		ny.Mul(ny, lam)
		ny.Sub(ny, cy)
		ny.Mod(ny, p)
		if ny.Sign() < 0 {
			ny.Add(ny, p)
		}
		cx, cy = nx, ny
		if (k>>uint(i))&1 == 1 {
			// Add G: lambda = (cy - y) / (cx - x)
			num := new(big.Int).Sub(cy, y)
			num.Mod(num, p)
			if num.Sign() < 0 {
				num.Add(num, p)
			}
			den := new(big.Int).Sub(cx, x)
			den.Mod(den, p)
			if den.Sign() < 0 {
				den.Add(den, p)
			}
			denInv := new(big.Int).Exp(den, new(big.Int).Sub(p, big.NewInt(2)), p)
			lam := new(big.Int).Mul(num, denInv)
			lam.Mod(lam, p)
			nx2 := new(big.Int).Mul(lam, lam)
			nx2.Sub(nx2, cx)
			nx2.Sub(nx2, x)
			nx2.Mod(nx2, p)
			if nx2.Sign() < 0 {
				nx2.Add(nx2, p)
			}
			ny2 := new(big.Int).Sub(cx, nx2)
			ny2.Mul(ny2, lam)
			ny2.Sub(ny2, cy)
			ny2.Mod(ny2, p)
			if ny2.Sign() < 0 {
				ny2.Add(ny2, p)
			}
			cx, cy = nx2, ny2
		}
	}
	return cx, cy
}

// TestBN254G1ScalarMul_Script verifies that EmitBN254G1ScalarMul computes k*G
// for small scalars. Tests k=1 (identity), k=2 (doubling), k=3 (3G).
func TestBN254G1ScalarMul_Script(t *testing.T) {
	gx := big.NewInt(1)
	gy := big.NewInt(2)
	x2, y2 := bn254ComputeDoubleG(t)
	x3, y3 := bn254ComputeAddG_2G(t)

	// Reference values for k=4..8 via bn254ComputeKG
	x4, y4 := bn254ComputeKG(t, 4)
	x5, y5 := bn254ComputeKG(t, 5)
	x6, y6 := bn254ComputeKG(t, 6)
	x7, y7 := bn254ComputeKG(t, 7)

	x100, y100 := bn254ComputeKG(t, 100)
	x1000, y1000 := bn254ComputeKG(t, 1000)
	x1024, y1024 := bn254ComputeKG(t, 1024)

	cases := []struct {
		name       string
		k          *big.Int
		expX, expY *big.Int
	}{
		{"1G", big.NewInt(1), gx, gy},
		{"2G", big.NewInt(2), x2, y2},
		{"3G", big.NewInt(3), x3, y3},
		{"4G", big.NewInt(4), x4, y4},
		{"5G", big.NewInt(5), x5, y5},
		{"6G", big.NewInt(6), x6, y6},
		{"7G", big.NewInt(7), x7, y7},
		{"100G", big.NewInt(100), x100, y100},
		{"1000G", big.NewInt(1000), x1000, y1000},
		{"1024G", big.NewInt(1024), x1024, y1024},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			mulOps := gatherOps(EmitBN254G1ScalarMul)

			var ops []StackOp
			// Stack: [G, k] -> EmitBN254G1ScalarMul -> [k*G]
			ops = append(ops, pushPoint(gx, gy))
			ops = append(ops, pushBigInt(tc.k))
			ops = append(ops, mulOps...)
			// Expected k*G
			ops = append(ops, pushPoint(tc.expX, tc.expY))
			ops = append(ops, opcode("OP_EQUALVERIFY"))
			ops = append(ops, opcode("OP_1"))

			if err := buildAndExecute(t, ops); err != nil {
				t.Fatalf("EmitBN254G1ScalarMul(G, %s) did not produce %s: %v",
					tc.k, tc.name, err)
			}
		})
	}
}

// BN254 G2 generator (from gnark-crypto ecc/bn254). Matches Rúnar's (real,
// imag) coordinate order: x0 = X.A0 = real, x1 = X.A1 = imag, etc.
func bn254G2Gen() (x0, x1, y0, y1 *big.Int) {
	x0, _ = new(big.Int).SetString("10857046999023057135944570762232829481370756359578518086990519993285655852781", 10)
	x1, _ = new(big.Int).SetString("11559732032986387107991004021392285783925812861821192530917403151452391805634", 10)
	y0, _ = new(big.Int).SetString("8495653923123431417604973247489272438418190587263600148770280649306958101930", 10)
	y1, _ = new(big.Int).SetString("4082367875863433681332203403145435568316851327593401208105741076214120093531", 10)
	return
}

// TestBN254MultiPairing4_Identity_Script verifies that EmitBN254MultiPairing4
// computes 1 in GT for an input that is algebraically guaranteed to satisfy
//
//	e(G, G2) * e(-G, G2) * e(G, G2) * e(-G, G2) == 1
//
// Bilinearity gives e(G, G2) * e(-G, G2) = e(G - G, G2) = e(O, G2) = 1,
// and repeating that twice still gives 1. This exercises the full Miller
// loop, final exponentiation, and Fp12 equality check through the actual
// script interpreter for the first time.
func TestBN254MultiPairing4_Identity_Script(t *testing.T) {
	gx := big.NewInt(1)
	gy := big.NewInt(2)
	p := new(big.Int).Set(bn254FieldP)
	negGy := new(big.Int).Sub(p, gy)

	g2x0, g2x1, g2y0, g2y1 := bn254G2Gen()

	pairingOps := gatherOps(EmitBN254MultiPairing4)

	var ops []StackOp
	// Pair 1: (G, G2)
	ops = append(ops, pushPoint(gx, gy))
	ops = append(ops, pushBigInt(g2x0))
	ops = append(ops, pushBigInt(g2x1))
	ops = append(ops, pushBigInt(g2y0))
	ops = append(ops, pushBigInt(g2y1))
	// Pair 2: (-G, G2)
	ops = append(ops, pushPoint(gx, negGy))
	ops = append(ops, pushBigInt(g2x0))
	ops = append(ops, pushBigInt(g2x1))
	ops = append(ops, pushBigInt(g2y0))
	ops = append(ops, pushBigInt(g2y1))
	// Pair 3: (G, G2)
	ops = append(ops, pushPoint(gx, gy))
	ops = append(ops, pushBigInt(g2x0))
	ops = append(ops, pushBigInt(g2x1))
	ops = append(ops, pushBigInt(g2y0))
	ops = append(ops, pushBigInt(g2y1))
	// Pair 4: (-G, G2)
	ops = append(ops, pushPoint(gx, negGy))
	ops = append(ops, pushBigInt(g2x0))
	ops = append(ops, pushBigInt(g2x1))
	ops = append(ops, pushBigInt(g2y0))
	ops = append(ops, pushBigInt(g2y1))

	ops = append(ops, pairingOps...)
	// Result: 1 (true) since the product is 1 in GT
	ops = append(ops, opcode("OP_VERIFY"))
	ops = append(ops, opcode("OP_1"))

	if err := buildAndExecute(t, ops); err != nil {
		t.Fatalf("e(G, G2) * e(-G, G2) * e(G, G2) * e(-G, G2) should equal 1: %v", err)
	}
}

// TestBN254G1OnCurve_Script verifies that EmitBN254G1OnCurve returns TRUE for
// the generator and FALSE for an invalid point.
func TestBN254G1OnCurve_Script(t *testing.T) {
	gx := big.NewInt(1)
	gy := big.NewInt(2)

	t.Run("generator", func(t *testing.T) {
		onCurveOps := gatherOps(EmitBN254G1OnCurve)
		var ops []StackOp
		ops = append(ops, pushPoint(gx, gy))
		ops = append(ops, onCurveOps...)
		// The result is left on the stack; OP_VERIFY consumes it.
		ops = append(ops, opcode("OP_VERIFY"))
		ops = append(ops, opcode("OP_1"))
		if err := buildAndExecute(t, ops); err != nil {
			t.Fatalf("G should be on curve: %v", err)
		}
	})

	t.Run("not_on_curve", func(t *testing.T) {
		onCurveOps := gatherOps(EmitBN254G1OnCurve)
		var ops []StackOp
		// (1, 3) is NOT on the curve since 3^2 = 9 != 1 + 3 = 4.
		ops = append(ops, pushPoint(big.NewInt(1), big.NewInt(3)))
		ops = append(ops, onCurveOps...)
		// Expect FALSE, so OP_NOT then OP_VERIFY should succeed.
		ops = append(ops, opcode("OP_NOT"))
		ops = append(ops, opcode("OP_VERIFY"))
		ops = append(ops, opcode("OP_1"))
		if err := buildAndExecute(t, ops); err != nil {
			t.Fatalf("(1,3) should NOT be on curve: %v", err)
		}
	})
}

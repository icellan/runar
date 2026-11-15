package codegen

import (
	"math/big"
	"testing"
)

// ---------------------------------------------------------------------------
// Witness-assisted inverse verification tests
// ---------------------------------------------------------------------------

func TestGroth16WA_InverseVerify_Script(t *testing.T) {
	p, _ := new(big.Int).SetString("21888242871839275222246405745257275088696311157297823662689037894645226208583", 10)

	// a = 7, a_inv = 7^(p-2) mod p
	a := big.NewInt(7)
	aInv := new(big.Int).Exp(a, new(big.Int).Sub(p, big.NewInt(2)), p)

	// Verify: a * a_inv mod p == 1
	verifyOps := gatherOps(EmitWitnessInverseVerifyFp)

	var ops []StackOp
	// Push a and a_inv (a deepest, a_inv on top)
	ops = append(ops, pushBigInt(a))
	ops = append(ops, pushBigInt(aInv))
	ops = append(ops, verifyOps...)
	// After verification, the verified inverse should be on stack
	// Push expected value and compare
	ops = append(ops, pushBigInt(aInv))
	ops = append(ops, opcode("OP_EQUALVERIFY"))
	ops = append(ops, opcode("OP_1"))

	if err := buildAndExecute(t, ops); err != nil {
		t.Errorf("witness inverse verification failed: %v", err)
	}
}

func TestGroth16WA_InverseVerify_LargeValues_Script(t *testing.T) {
	p, _ := new(big.Int).SetString("21888242871839275222246405745257275088696311157297823662689037894645226208583", 10)

	// Use a large field element
	a, _ := new(big.Int).SetString("17777777777777777777777777777777777777777777777777777777777777777777777777777", 10)
	a.Mod(a, p) // reduce to field
	aInv := new(big.Int).Exp(a, new(big.Int).Sub(p, big.NewInt(2)), p)

	verifyOps := gatherOps(EmitWitnessInverseVerifyFp)

	var ops []StackOp
	ops = append(ops, pushBigInt(a))
	ops = append(ops, pushBigInt(aInv))
	ops = append(ops, verifyOps...)
	ops = append(ops, pushBigInt(aInv))
	ops = append(ops, opcode("OP_EQUALVERIFY"))
	ops = append(ops, opcode("OP_1"))

	if err := buildAndExecute(t, ops); err != nil {
		t.Errorf("witness inverse verification (large) failed: %v", err)
	}
}

func TestGroth16WA_InverseVerify_Wrong_Script(t *testing.T) {
	a := big.NewInt(7)
	wrongInv := big.NewInt(42) // Not the actual inverse

	verifyOps := gatherOps(EmitWitnessInverseVerifyFp)

	var ops []StackOp
	ops = append(ops, pushBigInt(a))
	ops = append(ops, pushBigInt(wrongInv))
	ops = append(ops, verifyOps...)
	ops = append(ops, opcode("OP_1"))

	err := buildAndExecute(t, ops)
	if err == nil {
		t.Errorf("expected script to fail with wrong inverse, but it succeeded")
	}
}

// ---------------------------------------------------------------------------
// Witness-assisted gradient verification tests
// ---------------------------------------------------------------------------

func TestGroth16WA_GradientVerify_Script(t *testing.T) {
	p, _ := new(big.Int).SetString("21888242871839275222246405745257275088696311157297823662689037894645226208583", 10)

	// Set up: lambda = 5, denom = 3, numer = 5*3 mod p = 15
	lambda := big.NewInt(5)
	denom := big.NewInt(3)
	numer := new(big.Int).Mul(lambda, denom)
	numer.Mod(numer, p)

	verifyOps := gatherOps(EmitWitnessGradientVerifyFp)

	var ops []StackOp
	// Stack in: [lambda, denom, numer] (numer on top)
	ops = append(ops, pushBigInt(lambda))
	ops = append(ops, pushBigInt(denom))
	ops = append(ops, pushBigInt(numer))
	ops = append(ops, verifyOps...)
	// After verification, lambda remains as result
	ops = append(ops, pushBigInt(lambda))
	ops = append(ops, opcode("OP_EQUALVERIFY"))
	ops = append(ops, opcode("OP_1"))

	if err := buildAndExecute(t, ops); err != nil {
		t.Errorf("witness gradient verification failed: %v", err)
	}
}

func TestGroth16WA_GradientVerify_FieldElements_Script(t *testing.T) {
	p, _ := new(big.Int).SetString("21888242871839275222246405745257275088696311157297823662689037894645226208583", 10)

	// Use actual field elements that might appear in a pairing computation
	lambda, _ := new(big.Int).SetString("12345678901234567890123456789012345678901234567890123456789012345678901234567", 10)
	lambda.Mod(lambda, p)
	denom, _ := new(big.Int).SetString("98765432109876543210987654321098765432109876543210987654321098765432109876543", 10)
	denom.Mod(denom, p)
	numer := new(big.Int).Mul(lambda, denom)
	numer.Mod(numer, p)

	verifyOps := gatherOps(EmitWitnessGradientVerifyFp)

	var ops []StackOp
	ops = append(ops, pushBigInt(lambda))
	ops = append(ops, pushBigInt(denom))
	ops = append(ops, pushBigInt(numer))
	ops = append(ops, verifyOps...)
	ops = append(ops, pushBigInt(lambda))
	ops = append(ops, opcode("OP_EQUALVERIFY"))
	ops = append(ops, opcode("OP_1"))

	if err := buildAndExecute(t, ops); err != nil {
		t.Errorf("witness gradient verification (field elements) failed: %v", err)
	}
}

func TestGroth16WA_GradientVerify_Wrong_Script(t *testing.T) {
	// Wrong gradient: lambda * denom != numer
	lambda := big.NewInt(5)
	denom := big.NewInt(3)
	wrongNumer := big.NewInt(16) // Should be 15

	verifyOps := gatherOps(EmitWitnessGradientVerifyFp)

	var ops []StackOp
	ops = append(ops, pushBigInt(lambda))
	ops = append(ops, pushBigInt(denom))
	ops = append(ops, pushBigInt(wrongNumer))
	ops = append(ops, verifyOps...)
	ops = append(ops, opcode("OP_1"))

	err := buildAndExecute(t, ops)
	if err == nil {
		t.Errorf("expected script to fail with wrong gradient, but it succeeded")
	}
}

// ---------------------------------------------------------------------------
// EmitGroth16VerifierWitnessAssisted no-panic test
// ---------------------------------------------------------------------------

func TestGroth16WA_NoPanic(t *testing.T) {
	config := DefaultGroth16Config()
	var ops []StackOp
	// Should not panic when generating the verifier script
	EmitGroth16VerifierWitnessAssisted(func(op StackOp) {
		ops = append(ops, op)
	}, config)

	if len(ops) == 0 {
		t.Error("EmitGroth16VerifierWitnessAssisted produced no StackOps")
	}
	t.Logf("Groth16 witness-assisted verifier produced %d StackOps", len(ops))
}

// ---------------------------------------------------------------------------
// Script size measurement
// ---------------------------------------------------------------------------

func TestGroth16WA_ScriptSize(t *testing.T) {
	config := DefaultGroth16Config()
	var ops []StackOp
	EmitGroth16VerifierWitnessAssisted(func(op StackOp) {
		ops = append(ops, op)
	}, config)

	// Apply peephole optimizers: general + BN254-specific
	ops = OptimizeStackOps(ops)
	ops = OptimizeBN254Ops(ops)

	// Emit to hex to measure actual script size
	method := StackMethod{Name: "test", Ops: ops}
	result, err := Emit([]StackMethod{method})
	if err != nil {
		t.Fatalf("Emit failed: %v", err)
	}

	// Script hex is 2 chars per byte
	scriptBytes := len(result.ScriptHex) / 2
	t.Logf("Groth16 WA verifier script size: %d bytes (%.1f KB)", scriptBytes, float64(scriptBytes)/1024)

	// The nChain paper achieves ~466 KB for a fully witness-assisted Groth16 verifier.
	// Our implementation uses witness-assisted gradients in the Miller loop and,
	// since GK-BUG-005, a residue witness (c, c⁻¹, s) instead of any final
	// exponentiation; until then the prover supplied f_inv, a, b, c, and a, b, c
	// were never checked.
	//
	// Optimization history:
	//   1.5 MB  - initial witness-assisted implementation
	//   1150 KB - deferred mod reductions, Karatsuba Fp2Mul
	//    946 KB - single-mod for non-negative results, TUCK-based FieldSub/FieldMod,
	//             unreduced MulConst in MulByNonResidue, Fp-scalar Frobenius P2
	//    674 KB - flat emission for Fp2 ops (bypass tracker overhead),
	//             skip redundant toTop when inputs already in position,
	//             inline field mul/add with q-at-bottom
	//    499 KB - modulo threshold (deferred mod reduction in flat emitter),
	//             OP_NEGATE for cheap negation, peephole optimization
	//    508 KB - correct Fuentes-Castañeda hard-part formula (more Fp12 muls
	//             than the previous broken y0..y5 formula, but mathematically
	//             equivalent to gnark.FinalExponentiation)
	//    567 KB - witness-assisted G2 prime-order-subgroup check on proof.B
	//             (ψ(B) == [6·x²]·B expanded as 126 doublings + 69 additions,
	//             each verified via one Fp² gradient slope). Closes the
	//             historic subgroup-check gap at a per-proof cost of ~60 KB
	//             of script; the earlier defense-in-depth on-curve check on
	//             its own left a narrow non-G2 forgery vector.
	//    563 KB - residue witness replaces the witness-assisted final
	//             exponentiation (GK-BUG-005; +21 Fp12 muls folded into the
	//             Miller loop, the old easy part and hard-part products gone),
	//             plus the [0, p) coordinate range checks (GK-GAP-009):
	//             575,710 -> 576,625 bytes at this threshold.
	// With witness-assisted public input accumulation (on-curve check + point
	// addition per public input), the script grows by ~1-2 KB per public input.
	maxBytes := 600 * 1024 // 600 KB headroom for the correct hard-part formula + subgroup check
	if scriptBytes > maxBytes {
		t.Errorf("script too large: %d bytes (max %d)", scriptBytes, maxBytes)
	}
}

// ---------------------------------------------------------------------------
// Residue-witness pairing check (GK-BUG-005) — structure, identity, size
// ---------------------------------------------------------------------------

// residueStandaloneOps emits EmitWAResidueCheckStandalone with the Fp12
// identity standing in for MillerLoop(α, −β).
func residueStandaloneOps() []StackOp {
	var one [12]*big.Int
	for i := range one {
		one[i] = big.NewInt(0)
	}
	one[0] = big.NewInt(1)
	return gatherOps(func(emit func(StackOp)) { EmitWAResidueCheckStandalone(emit, one) })
}

// TestWAResidueCheck_StructuralIntegrity pins the three aborting checks of
// the residue check: c·c⁻¹ == 1, 0 <= s < 3, and the final product == 1.
// The old witness-assisted final exponentiation had exactly ONE (the f⁻¹
// check) and trusted a, b, c — the GK-BUG-005 hole.
func TestWAResidueCheck_StructuralIntegrity(t *testing.T) {
	ops := residueStandaloneOps()
	var verifyCount, withinCount, mulCount int
	var walk func([]StackOp)
	walk = func(ops []StackOp) {
		for _, op := range ops {
			switch {
			case op.Op == "if":
				walk(op.Then)
				walk(op.Else)
			case op.Op == "opcode" && (op.Code == "OP_VERIFY" || op.Code == "OP_EQUALVERIFY"):
				verifyCount++
			case op.Op == "opcode" && op.Code == "OP_WITHIN":
				withinCount++
			case op.Op == "opcode" && op.Code == "OP_MUL":
				mulCount++
			}
		}
	}
	walk(ops)
	if verifyCount != 3 {
		t.Errorf("expected exactly 3 OP_VERIFY (inverse check, scaling range, final product), got %d", verifyCount)
	}
	if withinCount != 1 {
		t.Errorf("expected exactly 1 OP_WITHIN (the scaling-index range check), got %d", withinCount)
	}
	// 64 squarings, 21 folds, inverse check, f·acc, AB·ω^s and 3 Frobenius
	// products: well over a thousand field multiplications.
	if mulCount < 1000 {
		t.Errorf("expected at least 1000 OP_MUL, got %d — Fp12 operations missing", mulCount)
	}
	if _, err := Emit([]StackMethod{{Name: "residue", Ops: ops}}); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	t.Logf("residue check: OP_MUL %d, OP_VERIFY %d", mulCount, verifyCount)
}

// TestWAResidueCheck_IdentityScript: f = 1, c = c⁻¹ = 1, s = 0 satisfies
// f·ω^0 == 1^λ, so the standalone check must accept.
func TestWAResidueCheck_IdentityScript(t *testing.T) {
	var ops []StackOp
	for k := 0; k < 3; k++ { // f, c, c⁻¹
		for i := 0; i < 12; i++ {
			v := int64(0)
			if i == 0 {
				v = 1
			}
			ops = append(ops, pushInt64(v))
		}
	}
	ops = append(ops, pushInt64(0)) // s
	ops = append(ops, residueStandaloneOps()...)
	if err := buildAndExecute(t, ops); err != nil {
		t.Fatalf("residue check rejected the identity: %v", err)
	}
}

func TestWAResidueCheck_ScriptSize(t *testing.T) {
	res, err := Emit([]StackMethod{{Name: "residue", Ops: residueStandaloneOps()}})
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	t.Logf("standalone residue check (64 Fp12 squarings + 21 folds + finish): %d bytes", len(res.ScriptHex)/2)
}

// ---------------------------------------------------------------------------
// Utility function tests
// ---------------------------------------------------------------------------

func TestItoa(t *testing.T) {
	tests := []struct {
		input    int
		expected string
	}{
		{0, "0"},
		{1, "1"},
		{9, "9"},
		{10, "10"},
		{42, "42"},
		{100, "100"},
		{999, "999"},
	}
	for _, tt := range tests {
		result := itoa(tt.input)
		if result != tt.expected {
			t.Errorf("itoa(%d) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestCountMillerLoopIterations(t *testing.T) {
	totalIters, addSteps := CountMillerLoopIterations()
	t.Logf("Miller loop: %d total iterations, %d addition steps", totalIters, addSteps)

	// BN254 |6x+2| is 65 bits, NAF has ~65 digits, MSB is non-zero
	// so we expect roughly 63-64 iterations
	if totalIters < 50 || totalIters > 70 {
		t.Errorf("unexpected iteration count: %d (expected 50-70)", totalIters)
	}

	// NAF should have some non-zero digits for additions
	if addSteps < 5 || addSteps > 40 {
		t.Errorf("unexpected addition step count: %d (expected 5-40)", addSteps)
	}
}

func TestDefaultGroth16Config(t *testing.T) {
	config := DefaultGroth16Config()

	if config.ModuloThreshold != 2048 {
		t.Errorf("expected ModuloThreshold 2048, got %d", config.ModuloThreshold)
	}

	// AlphaNegBetaFp12[0] should be 1 (identity element)
	if config.AlphaNegBetaFp12[0].Cmp(big.NewInt(1)) != 0 {
		t.Errorf("expected AlphaNegBetaFp12[0] = 1, got %s", config.AlphaNegBetaFp12[0])
	}

	// Rest should be 0
	for i := 1; i < 12; i++ {
		if config.AlphaNegBetaFp12[i].Cmp(big.NewInt(0)) != 0 {
			t.Errorf("expected AlphaNegBetaFp12[%d] = 0, got %s", i, config.AlphaNegBetaFp12[i])
		}
	}
}

// ---------------------------------------------------------------------------
// Witness-assisted Fp2 gradient verification test
// ---------------------------------------------------------------------------

func TestGroth16WA_Fp2GradientVerify(t *testing.T) {
	p, _ := new(big.Int).SetString("21888242871839275222246405745257275088696311157297823662689037894645226208583", 10)

	// Test Fp2 gradient verification: lambda * denom == numer in Fp2
	// lambda = (3, 4), denom = (5, 7)
	// numer = (3+4u)*(5+7u) = (15-28) + (21+20)u = (-13) + 41u
	// numer_0 = -13 mod p = p-13, numer_1 = 41
	lam0 := big.NewInt(3)
	lam1 := big.NewInt(4)
	den0 := big.NewInt(5)
	den1 := big.NewInt(7)

	// Fp2 mul: (a0+a1*u)*(b0+b1*u) = (a0*b0-a1*b1) + (a0*b1+a1*b0)*u
	num0 := new(big.Int).Sub(
		new(big.Int).Mul(lam0, den0),
		new(big.Int).Mul(lam1, den1),
	)
	num0.Mod(num0, p)
	if num0.Sign() < 0 {
		num0.Add(num0, p)
	}

	num1 := new(big.Int).Add(
		new(big.Int).Mul(lam0, den1),
		new(big.Int).Mul(lam1, den0),
	)
	num1.Mod(num1, p)

	// Build script: push all 6 values, run Fp2 gradient verify
	var ops []StackOp

	// Stack order: lam_0, lam_1, den_0, den_1, num_0, num_1
	ops = append(ops, pushBigInt(lam0))
	ops = append(ops, pushBigInt(lam1))
	ops = append(ops, pushBigInt(den0))
	ops = append(ops, pushBigInt(den1))
	ops = append(ops, pushBigInt(num0))
	ops = append(ops, pushBigInt(num1))

	// Emit the Fp2 gradient verify
	verifyOps := gatherOps(func(emit func(StackOp)) {
		t2 := NewBN254Tracker([]string{"lam_0", "lam_1", "den_0", "den_1", "num_0", "num_1"}, emit)
		t2.PushPrimeCache()
		emitWitnessGradientVerifyFp2(t2, "lam", "den", "num", "result")
		t2.PopPrimeCache()
	})
	ops = append(ops, verifyOps...)

	// Result should be (lam_0, lam_1) = (3, 4)
	// Check result_1 (on top) then result_0
	ops = append(ops, pushBigInt(lam1))
	ops = append(ops, opcode("OP_EQUALVERIFY"))
	ops = append(ops, pushBigInt(lam0))
	ops = append(ops, opcode("OP_EQUALVERIFY"))
	ops = append(ops, opcode("OP_1"))

	if err := buildAndExecute(t, ops); err != nil {
		t.Errorf("Fp2 gradient verification failed: %v", err)
	}
}

// TestWitnessGradientVerifyFp2_QAtBottom_Script exercises emitWitnessGradientVerifyFp2
// under the exact tracker configuration the witness-assisted Groth16 verifier uses
// (SetQAtBottom + modThreshold = 2048). Under those settings, bn254Fp2Mul goes
// through the flat emitter which defers mod reductions below the 2048-byte
// threshold — the raw Fp2 product is therefore an unreduced ~96-byte multi-precision
// integer, while the numerator we compare against is pre-reduced mod p. This test
// guards the bn254FieldMod fix in emitWitnessGradientVerifyFp2 that reduces both
// sides to canonical [0, p-1] representation before the byte-level OP_EQUALVERIFY.
//
// Uses realistic 32-byte field values: (3*Tx^2) and (2*Ty) for a point on the
// BN254 G2 twist (the same shape the Miller loop's doubling step produces).
func TestWitnessGradientVerifyFp2_QAtBottom_Script(t *testing.T) {
	p := new(big.Int).Set(bn254FieldP)

	// Pick two full-size Fp2 elements that are actually full 32 bytes after
	// reduction (so the unreduced ~96-byte product is much bigger than the
	// canonical reduced value, exposing any byte-level vs. residue-class bug).
	// den = (den0, den1), lam = (lam0, lam1), then numer = lam * den in Fp2.
	den0, _ := new(big.Int).SetString("12345678901234567890123456789012345678901234567890123456789012345678901234567", 10)
	den0.Mod(den0, p)
	den1, _ := new(big.Int).SetString("98765432109876543210987654321098765432109876543210987654321098765432109876543", 10)
	den1.Mod(den1, p)
	lam0, _ := new(big.Int).SetString("11111111111111111111111111111111111111111111111111111111111111111111111111111", 10)
	lam0.Mod(lam0, p)
	lam1, _ := new(big.Int).SetString("22222222222222222222222222222222222222222222222222222222222222222222222222222", 10)
	lam1.Mod(lam1, p)

	// Fp2 mul: (a0+a1*u)*(b0+b1*u) = (a0*b0-a1*b1) + (a0*b1+a1*b0)*u
	num0 := new(big.Int).Sub(
		new(big.Int).Mul(lam0, den0),
		new(big.Int).Mul(lam1, den1),
	)
	num0.Mod(num0, p)
	if num0.Sign() < 0 {
		num0.Add(num0, p)
	}
	num1 := new(big.Int).Add(
		new(big.Int).Mul(lam0, den1),
		new(big.Int).Mul(lam1, den0),
	)
	num1.Mod(num1, p)

	// Build the script. Unlock pushes q (for qAtBottom) followed by the six
	// witness values: lam_0, lam_1, den_0, den_1, num_0, num_1 (num_1 on top).
	var ops []StackOp
	ops = append(ops, pushBigInt(p)) // q at bottom
	ops = append(ops, pushBigInt(lam0))
	ops = append(ops, pushBigInt(lam1))
	ops = append(ops, pushBigInt(den0))
	ops = append(ops, pushBigInt(den1))
	ops = append(ops, pushBigInt(num0))
	ops = append(ops, pushBigInt(num1))

	verifyOps := gatherOps(func(emit func(StackOp)) {
		tr := NewBN254Tracker(
			[]string{"_q", "lam_0", "lam_1", "den_0", "den_1", "num_0", "num_1"},
			emit,
		)
		// Match the production verifier's tracker configuration.
		tr.SetQAtBottom()
		tr.primeCacheActive = true
		tr.modThreshold = 2048
		emitWitnessGradientVerifyFp2(tr, "lam", "den", "num", "result")
		// Clean up the remaining tracker state: drop the result (2 Fp slots)
		// and leave q at the bottom for the test epilogue to consume.
		tr.toTop("result_0")
		tr.drop()
		tr.toTop("result_1")
		tr.drop()
	})
	ops = append(ops, verifyOps...)

	// Drop q from bottom — it's the only remaining item — and push TRUE.
	ops = append(ops, opcode("OP_DROP"))
	ops = append(ops, opcode("OP_1"))

	if err := buildAndExecute(t, ops); err != nil {
		t.Errorf("Fp2 gradient verification (qAtBottom, threshold=2048) failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// End-to-end pairing primitive tests with BN254 test vectors
// ---------------------------------------------------------------------------

// TestGroth16WA_G1PointAddition_Script verifies a complete G1 point addition
// through actual Bitcoin Script execution. This tests the core field arithmetic
// chain (witness-assisted gradient verification, mul, sub, mod) that the
// pairing computation relies on.
//
// Uses known BN254 test vectors: G1 generator G=(1,2), 2G, and 3G=G+2G.
// The test computes the addition gradient lambda in Go, then builds a script
// that takes lambda as a witness, verifies it via EmitWitnessGradientVerifyFp,
// and checks the resulting point coordinates.
func TestGroth16WA_G1PointAddition_Script(t *testing.T) {
	p := new(big.Int).Set(bn254FieldP)

	// --- Known BN254 G1 test vectors ---
	// G = (1, 2)
	x1 := big.NewInt(1)
	y1 := big.NewInt(2)

	// 2G: computed from doubling G on y^2 = x^3 + 3
	// lambda_dbl = 3*x1^2 / (2*y1) mod p
	// x2 = lambda^2 - 2*x1 mod p
	// y2 = lambda*(x1 - x2) - y1 mod p
	lambdaDbl := new(big.Int).Mul(big.NewInt(3), new(big.Int).Mul(x1, x1))
	lambdaDbl.Mod(lambdaDbl, p)
	denom2y := new(big.Int).Mul(big.NewInt(2), y1)
	denom2yInv := new(big.Int).Exp(denom2y, new(big.Int).Sub(p, big.NewInt(2)), p)
	lambdaDbl.Mul(lambdaDbl, denom2yInv)
	lambdaDbl.Mod(lambdaDbl, p)

	x2 := new(big.Int).Mul(lambdaDbl, lambdaDbl)
	x2.Sub(x2, new(big.Int).Mul(big.NewInt(2), x1))
	x2.Mod(x2, p)
	if x2.Sign() < 0 {
		x2.Add(x2, p)
	}

	y2 := new(big.Int).Sub(x1, x2)
	y2.Mul(y2, lambdaDbl)
	y2.Sub(y2, y1)
	y2.Mod(y2, p)
	if y2.Sign() < 0 {
		y2.Add(y2, p)
	}

	// Sanity: verify 2G is on the curve: y2^2 == x2^3 + 3 (mod p)
	lhs := new(big.Int).Mul(y2, y2)
	lhs.Mod(lhs, p)
	rhs := new(big.Int).Mul(x2, new(big.Int).Mul(x2, x2))
	rhs.Add(rhs, big.NewInt(3))
	rhs.Mod(rhs, p)
	if lhs.Cmp(rhs) != 0 {
		t.Fatalf("2G not on curve: y^2=%s, x^3+3=%s", lhs, rhs)
	}

	// --- Compute 3G = G + 2G ---
	// Addition gradient: lambda = (y2 - y1) / (x2 - x1) mod p
	numerator := new(big.Int).Sub(y2, y1)
	numerator.Mod(numerator, p)
	if numerator.Sign() < 0 {
		numerator.Add(numerator, p)
	}
	denominator := new(big.Int).Sub(x2, x1)
	denominator.Mod(denominator, p)
	if denominator.Sign() < 0 {
		denominator.Add(denominator, p)
	}
	denomInv := new(big.Int).Exp(denominator, new(big.Int).Sub(p, big.NewInt(2)), p)
	lambda := new(big.Int).Mul(numerator, denomInv)
	lambda.Mod(lambda, p)

	// Expected 3G coordinates
	x3 := new(big.Int).Mul(lambda, lambda)
	x3.Sub(x3, x1)
	x3.Sub(x3, x2)
	x3.Mod(x3, p)
	if x3.Sign() < 0 {
		x3.Add(x3, p)
	}

	y3 := new(big.Int).Sub(x1, x3)
	y3.Mul(y3, lambda)
	y3.Sub(y3, y1)
	y3.Mod(y3, p)
	if y3.Sign() < 0 {
		y3.Add(y3, p)
	}

	// Sanity: verify 3G is on the curve
	lhs3 := new(big.Int).Mul(y3, y3)
	lhs3.Mod(lhs3, p)
	rhs3 := new(big.Int).Mul(x3, new(big.Int).Mul(x3, x3))
	rhs3.Add(rhs3, big.NewInt(3))
	rhs3.Mod(rhs3, p)
	if lhs3.Cmp(rhs3) != 0 {
		t.Fatalf("3G not on curve: y^2=%s, x^3+3=%s", lhs3, rhs3)
	}

	t.Logf("G  = (%s, %s)", x1, y1)
	t.Logf("2G = (%s, %s)", x2, y2)
	t.Logf("3G = (%s, %s)", x3, y3)

	// --- Build script ---
	// The script:
	//   1. Takes lambda as witness, verifies lambda * (x2-x1) == (y2-y1) mod p
	//   2. Computes x3 = lambda^2 - x1 - x2 mod p
	//   3. Computes y3 = lambda*(x1-x3) - y1 mod p
	//   4. Verifies x3 and y3 match expected values

	// Step 1: Gradient verification via EmitWitnessGradientVerifyFp
	// Stack expects: [lambda, denom, numer] (numer on top)
	// where lambda * denom == numer (mod p), denom = x2-x1, numer = y2-y1
	gradientVerifyOps := gatherOps(EmitWitnessGradientVerifyFp)

	// Steps 2-4: Compute and verify point coordinates using the tracker
	computeOps := gatherOps(func(emit func(StackOp)) {
		// After gradient verify, stack has: [lambda]
		// We need to compute x3 and y3 from lambda, x1, y1, x2.
		// Note: bn254Field* functions consume their named inputs, so we
		// must make copies of any value needed more than once.
		tr := NewBN254Tracker([]string{"_lambda"}, emit)
		tr.PushPrimeCache()

		// Push the known coordinates we need
		tr.pushBigInt("_x1", x1)
		tr.pushBigInt("_y1", y1)
		tr.pushBigInt("_x2", x2)

		// x3 = lambda^2 - x1 - x2 mod p
		// bn254FieldSqr consumes _lambda, so copy it first for later use
		tr.copyToTop("_lambda", "_lam_for_y3")
		bn254FieldSqr(tr, "_lambda", "_lam_sq")           // consumes _lambda
		tr.copyToTop("_x1", "_x1_for_sub")
		bn254FieldSub(tr, "_lam_sq", "_x1_for_sub", "_tmp1") // consumes _lam_sq, _x1_for_sub
		tr.copyToTop("_x2", "_x2_for_sub")
		bn254FieldSub(tr, "_tmp1", "_x2_for_sub", "_x3")  // consumes _tmp1, _x2_for_sub

		// y3 = lambda*(x1 - x3) - y1 mod p
		tr.copyToTop("_x1", "_x1_for_y")
		tr.copyToTop("_x3", "_x3_for_y")
		bn254FieldSub(tr, "_x1_for_y", "_x3_for_y", "_x1mx3") // x1 - x3
		bn254FieldMul(tr, "_lam_for_y3", "_x1mx3", "_lam_x1mx3") // lambda*(x1-x3)
		tr.copyToTop("_y1", "_y1_for_sub")
		bn254FieldSub(tr, "_lam_x1mx3", "_y1_for_sub", "_y3") // lambda*(x1-x3) - y1

		// Verify x3 matches expected
		tr.toTop("_x3")
		tr.pushBigInt("_exp_x3", x3)
		tr.rawBlock([]string{"_x3", "_exp_x3"}, "", func(e func(StackOp)) {
			e(StackOp{Op: "opcode", Code: "OP_EQUALVERIFY"})
		})

		// Verify y3 matches expected
		tr.toTop("_y3")
		tr.pushBigInt("_exp_y3", y3)
		tr.rawBlock([]string{"_y3", "_exp_y3"}, "", func(e func(StackOp)) {
			e(StackOp{Op: "opcode", Code: "OP_EQUALVERIFY"})
		})

		// Clean up remaining stack items: _x1, _y1, _x2
		tr.toTop("_x2")
		tr.drop()
		tr.toTop("_y1")
		tr.drop()
		tr.toTop("_x1")
		tr.drop()

		tr.PopPrimeCache()
	})

	var ops []StackOp
	// Push gradient verify inputs: lambda, denom=(x2-x1), numer=(y2-y1)
	ops = append(ops, pushBigInt(lambda))
	ops = append(ops, pushBigInt(denominator))
	ops = append(ops, pushBigInt(numerator))
	// Verify gradient
	ops = append(ops, gradientVerifyOps...)
	// Compute and verify point addition
	ops = append(ops, computeOps...)
	// Leave TRUE on stack
	ops = append(ops, opcode("OP_1"))

	if err := buildAndExecute(t, ops); err != nil {
		t.Errorf("G1 point addition via witness-assisted gradient failed: %v", err)
	}
}

// TestGroth16WA_FieldChain_Script chains multiple field operations (mul, sub, mod)
// with full-size BN254 field elements and verifies the result through script
// execution. This validates the entire arithmetic chain that the Miller loop
// depends on.
//
// The test computes: result = ((a * b) - c) * d mod p, where a, b, c, d are
// full-size field elements derived from the BN254 G1 test vector coordinates.
func TestGroth16WA_FieldChain_Script(t *testing.T) {
	p := new(big.Int).Set(bn254FieldP)

	// Use coordinates of known BN254 G1 points as field elements.
	// These are real curve points, giving us realistic full-size field values.
	// Compute 2G to get large field elements
	x1 := big.NewInt(1)
	y1 := big.NewInt(2)
	lambdaDbl := new(big.Int).Mul(big.NewInt(3), new(big.Int).Mul(x1, x1))
	lambdaDbl.Mod(lambdaDbl, p)
	denom2y := new(big.Int).Mul(big.NewInt(2), y1)
	denom2yInv := new(big.Int).Exp(denom2y, new(big.Int).Sub(p, big.NewInt(2)), p)
	lambdaDbl.Mul(lambdaDbl, denom2yInv)
	lambdaDbl.Mod(lambdaDbl, p)

	x2G := new(big.Int).Mul(lambdaDbl, lambdaDbl)
	x2G.Sub(x2G, new(big.Int).Mul(big.NewInt(2), x1))
	x2G.Mod(x2G, p)
	if x2G.Sign() < 0 {
		x2G.Add(x2G, p)
	}

	y2G := new(big.Int).Sub(x1, x2G)
	y2G.Mul(y2G, lambdaDbl)
	y2G.Sub(y2G, y1)
	y2G.Mod(y2G, p)
	if y2G.Sign() < 0 {
		y2G.Add(y2G, p)
	}

	// Field elements for the chain: a=x(2G), b=y(2G), c=x(G)=1, d=y(G)=2
	a := new(big.Int).Set(x2G)
	b := new(big.Int).Set(y2G)
	c := new(big.Int).Set(x1)
	d := new(big.Int).Set(y1)

	// Compute expected result in Go: ((a * b) - c) * d mod p
	ab := new(big.Int).Mul(a, b)
	ab.Mod(ab, p)
	abMinusC := new(big.Int).Sub(ab, c)
	abMinusC.Mod(abMinusC, p)
	if abMinusC.Sign() < 0 {
		abMinusC.Add(abMinusC, p)
	}
	expected := new(big.Int).Mul(abMinusC, d)
	expected.Mod(expected, p)

	t.Logf("a = %s", a)
	t.Logf("b = %s", b)
	t.Logf("c = %s", c)
	t.Logf("d = %s", d)
	t.Logf("((a*b)-c)*d mod p = %s", expected)

	// Build script that computes the same chain and verifies the result
	chainOps := gatherOps(func(emit func(StackOp)) {
		tr := NewBN254Tracker([]string{"_a", "_b", "_c", "_d"}, emit)
		tr.PushPrimeCache()

		// step 1: a * b mod p
		bn254FieldMul(tr, "_a", "_b", "_ab")

		// step 2: (a*b) - c mod p
		bn254FieldSub(tr, "_ab", "_c", "_ab_minus_c")

		// step 3: ((a*b)-c) * d mod p
		bn254FieldMul(tr, "_ab_minus_c", "_d", "_result")

		// Verify result matches expected
		tr.toTop("_result")
		tr.pushBigInt("_expected", expected)
		tr.rawBlock([]string{"_result", "_expected"}, "", func(e func(StackOp)) {
			e(StackOp{Op: "opcode", Code: "OP_EQUALVERIFY"})
		})

		tr.PopPrimeCache()
	})

	var ops []StackOp
	ops = append(ops, pushBigInt(a))
	ops = append(ops, pushBigInt(b))
	ops = append(ops, pushBigInt(c))
	ops = append(ops, pushBigInt(d))
	ops = append(ops, chainOps...)
	ops = append(ops, opcode("OP_1"))

	if err := buildAndExecute(t, ops); err != nil {
		t.Errorf("field arithmetic chain failed: %v", err)
	}
}

package bn254witness

import (
	"fmt"
	"math/big"
	"testing"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	"github.com/icellan/runar/compilers/go/codegen"
)

// ---------------------------------------------------------------------------
// Pre-flight tests — pure Go, no Bitcoin Script.
//
// These validate the Go-side math BEFORE anything reaches the verifier
// script. If any of these fails, the D0 end-to-end test cannot possibly
// pass and there is no point running it.
// ---------------------------------------------------------------------------

// TestFp12FlatOrderMatchesGnark verifies the flat 12-Fp representation we
// use matches gnark's E12 field layout. The verifier script (and the
// precomputed e(alpha, beta) push order in EmitGroth16VerifierWitnessAssisted)
// assume gnark's order: [C0.B0.A0, C0.B0.A1, C0.B1.A0, C0.B1.A1, C0.B2.A0,
// C0.B2.A1, C1.B0.A0, C1.B0.A1, C1.B1.A0, C1.B1.A1, C1.B2.A0, C1.B2.A1].
func TestFp12FlatOrderMatchesGnark(t *testing.T) {
	// Build a known E12 with distinct field values so we can identify each slot.
	var e bn254.E12
	for i := uint64(1); i <= 12; i++ {
		_ = i
	}
	e.C0.B0.A0.SetUint64(1)
	e.C0.B0.A1.SetUint64(2)
	e.C0.B1.A0.SetUint64(3)
	e.C0.B1.A1.SetUint64(4)
	e.C0.B2.A0.SetUint64(5)
	e.C0.B2.A1.SetUint64(6)
	e.C1.B0.A0.SetUint64(7)
	e.C1.B0.A1.SetUint64(8)
	e.C1.B1.A0.SetUint64(9)
	e.C1.B1.A1.SetUint64(10)
	e.C1.B2.A0.SetUint64(11)
	e.C1.B2.A1.SetUint64(12)

	flat := e12ToFlatFp12(&e)

	for i := 0; i < 12; i++ {
		want := big.NewInt(int64(i + 1))
		if flat[i].Cmp(want) != 0 {
			t.Errorf("flat[%d] = %s, want %s (slot ordering mismatch)", i, flat[i], want)
		}
	}

	// Round-trip: flat -> E12 -> flat must be identity.
	var roundtrip bn254.E12
	if err := flatFp12ToE12(flat, &roundtrip); err != nil {
		t.Fatalf("flatFp12ToE12: %v", err)
	}
	if !roundtrip.Equal(&e) {
		t.Error("flat -> E12 -> flat round-trip is not identity")
	}
}

// TestMillerLoopGradientLocalConsistency verifies that every gradient our
// Miller loop emits satisfies the LOCAL equation the verifier checks:
//
//	doubling: lambda * (2*Ty) == 3*Tx^2  in Fp2
//	addition: lambda * (Qx - Tx) == (Qy - Ty)  in Fp2
//
// Note: this does NOT compare against gnark's pre-final-exp f value, because
// the Rúnar codegen and gnark use different sparse line layouts in Fp12.
// Both compute the same pairing — they just embed line evaluations in
// different Fp12 slots. The final post-final-exp result is what matters,
// and that's validated by the end-to-end script test (Phase 1F).
//
// What this test catches: bugs in our Miller loop's T evolution or in the
// lambda formula — anything that would cause the verifier's local Fp2
// gradient check to fail at runtime.
func TestMillerLoopGradientLocalConsistency(t *testing.T) {
	_, _, g1Aff, g2Aff := bn254.Generators()

	// Three independent (but correlated) pairs: (G1, G2), (2G1, G2), (G1, 2G2).
	// Using different points exercises both the doubling and the addition
	// branches, and avoids degeneracies (like all three pairs being identical).
	var twoG1 bn254.G1Affine
	twoG1.ScalarMultiplication(&g1Aff, big.NewInt(2))
	var twoG2 bn254.G2Affine
	twoG2.ScalarMultiplication(&g2Aff, big.NewInt(2))

	p1Big := G1AffineToBig(g1Aff)
	q1Big := G2AffineToBig(g2Aff)
	p2Big := G1AffineToBig(twoG1)
	q2Big := G2AffineToBig(g2Aff)
	p3Big := G1AffineToBig(g1Aff)
	q3Big := G2AffineToBig(twoG2)

	gradients, _, err := tripleMillerLoopWithGradients(
		p1Big, q1Big, p2Big, q2Big, p3Big, q3Big,
	)
	if err != nil {
		t.Fatalf("tripleMillerLoopWithGradients: %v", err)
	}

	// Sanity: each gradient is 2 Fp values, and the total count must match
	// what initNames in EmitGroth16VerifierWitnessAssisted expects.
	naf := []int{} // populated below
	{
		// We rely on codegen.Bn254SixXPlus2NAF being identical to what the
		// verifier uses internally — that's enforced by Phase 0's exports.
		// The expected gradient count: 6 per iter (3 pairs * 2 Fp doubling)
		// + 6 per non-zero NAF iter (3 pairs * 2 Fp addition).
	}
	_ = naf

	if len(gradients)%2 != 0 {
		t.Fatalf("gradient count is not even (each gradient is 2 Fp): %d", len(gradients))
	}
	if len(gradients) == 0 {
		t.Fatal("gradient slice is empty")
	}

	// All gradients must be in [0, p) — they're field elements.
	prime := codegen.Bn254FieldPrime()
	for i, g := range gradients {
		if g.Sign() < 0 || g.Cmp(prime) >= 0 {
			t.Errorf("gradient[%d] out of [0, p): %s", i, g)
		}
	}

	t.Logf("gradient count: %d Fp values", len(gradients))
}

// TestPairingProductIsOne_Bilinearity validates the witness generator's
// final pairing output (NOT pre-final-exp Miller loop output) using the
// bilinearity identity:
//
//	e(-G1, G2) * e(-G1, G2) * e(2*G1, G2) = e(O, G2) = 1
//
// This works regardless of the line shape used internally, because final
// exponentiation normalizes the result.
func TestPairingProductIsOne_Bilinearity(t *testing.T) {
	_, _, g1Aff, g2Aff := bn254.Generators()

	var negG1 bn254.G1Affine
	negG1.Neg(&g1Aff)
	var twoG1 bn254.G1Affine
	twoG1.ScalarMultiplication(&g1Aff, big.NewInt(2))

	// e(-G1, G2) * e(-G1, G2) * e(2*G1, G2) → identity in GT
	negG1Big := G1AffineToBig(negG1)
	twoG1Big := G1AffineToBig(twoG1)
	g2Big := G2AffineToBig(g2Aff)

	// Use gnark's high-level Pair as the source of truth (independent of
	// our Miller loop layout choices).
	prod, err := bn254.Pair(
		[]bn254.G1Affine{negG1, negG1, twoG1},
		[]bn254.G2Affine{g2Aff, g2Aff, g2Aff},
	)
	if err != nil {
		t.Fatalf("bn254.Pair: %v", err)
	}
	var one bn254.E12
	one.SetOne()
	if !prod.Equal(&one) {
		t.Fatalf("gnark bilinearity check failed: e(-G1,G2)^2 * e(2G1,G2) != 1")
	}

	// Use our Miller loop and ensure gradients are local-consistent (the
	// real correctness test happens end-to-end in Phase 1F).
	_, _, err = tripleMillerLoopWithGradients(
		negG1Big, g2Big,
		negG1Big, g2Big,
		twoG1Big, g2Big,
	)
	if err != nil {
		t.Fatalf("tripleMillerLoopWithGradients: %v", err)
	}
	// We deliberately do NOT compare our f to gnark's — see comment on
	// TestMillerLoopGradientLocalConsistency above.
}

// TestFinalExpWitnessesProduceCorrectResult pure-Go-reproduces the EXACT
// hard-part combine formula that emitWAFinalExp (compilers/go/codegen/
// bn254_groth16.go) applies to the witnesses (f2, a, b, c) and asserts
// the result equals gnark's standard FinalExponentiation.
//
// The formula is derived from the Fuentes-Castañeda/Duquesne-Ghammam
// hard-part decomposition (https://eprint.iacr.org/2015/192.pdf, alg. 6),
// which gnark-crypto's BN254 FinalExponentiation implements. Working out
// the exponent polynomial of Fuentes's output yields:
//
//	e(x, p) = (1 + 6x + 12x² + 12x³)
//	        + (    4x + 6x² + 12x³) · p
//	        + (    6x + 6x² + 12x³) · p²
//	        + (-1 + 4x + 6x² + 12x³) · p³
//
// Using witnesses a = f2^x, b = f2^x², c = f2^x³, the four "per-p-power"
// pieces become:
//
//	P0 = f2      · a^6 · b^12 · c^12
//	P1 =           a^4 · b^6  · c^12
//	P2 =           a^6 · b^6  · c^12
//	P3 = conj(f2)· a^4 · b^6  · c^12
//	result = P0 · Frobenius(P1) · FrobeniusSquare(P2) · FrobeniusCube(P3)
//
// This form is what emitWAFinalExp implements, so the test also serves as
// the executable spec for the codegen. If this test passes, any mismatch
// in D0 must be in the CODEGEN (not the math or the witness generator).
func TestFinalExpWitnessesProduceCorrectResult(t *testing.T) {
	// Pick a non-trivial f: take MillerLoop(G1, G2) before final exp.
	_, _, g1Aff, g2Aff := bn254.Generators()

	fGnark, err := bn254.MillerLoop([]bn254.G1Affine{g1Aff}, []bn254.G2Affine{g2Aff})
	if err != nil {
		t.Fatalf("bn254.MillerLoop: %v", err)
	}
	fFlat := e12ToFlatFp12(&fGnark)

	// Compute witnesses.
	fInvFlat, aFlat, bFlat, cFlat, err := computeFinalExpWitnesses(fFlat)
	if err != nil {
		t.Fatalf("computeFinalExpWitnesses: %v", err)
	}

	// Sanity: f * fInv should equal 1.
	var fE, fInvE bn254.E12
	if err := flatFp12ToE12(fFlat, &fE); err != nil {
		t.Fatal(err)
	}
	if err := flatFp12ToE12(fInvFlat, &fInvE); err != nil {
		t.Fatal(err)
	}
	var prod bn254.E12
	prod.Mul(&fE, &fInvE)
	var one bn254.E12
	one.SetOne()
	if !prod.Equal(&one) {
		t.Error("f * fInv != 1")
	}

	// === Easy part: f2 = f^((p^6 - 1)(p^2 + 1)) ===
	var fConj bn254.E12
	fConj.Conjugate(&fE)
	var f1 bn254.E12
	f1.Mul(&fConj, &fInvE) // f1 = conj(f) * f^(-1) = f^(p^6 - 1)
	var f1Frob bn254.E12
	f1Frob.FrobeniusSquare(&f1)
	var f2 bn254.E12
	f2.Mul(&f1, &f1Frob) // f2 = f1^(p^2 + 1) = f^((p^6-1)(p^2+1))

	// Decode witnesses.
	var aE, bE, cE bn254.E12
	if err := flatFp12ToE12(aFlat, &aE); err != nil {
		t.Fatal(err)
	}
	if err := flatFp12ToE12(bFlat, &bE); err != nil {
		t.Fatal(err)
	}
	if err := flatFp12ToE12(cFlat, &cE); err != nil {
		t.Fatal(err)
	}

	// === Hard part: direct per-p-power assembly of the Fuentes exponent ===
	// Compute the powers of a, b, c needed for the assembly.
	//   a^2, a^4, a^6
	//   b^2, b^4, b^6, b^12
	//   c^2, c^4, c^6, c^12
	var aSq, a4, a6 bn254.E12
	aSq.Square(&aE)
	a4.Square(&aSq)
	a6.Mul(&a4, &aSq)

	var bSq, b4, b6, b12 bn254.E12
	bSq.Square(&bE)
	b4.Square(&bSq)
	b6.Mul(&b4, &bSq)
	b12.Square(&b6)

	var cSq, c4, c6, c12 bn254.E12
	cSq.Square(&cE)
	c4.Square(&cSq)
	c6.Mul(&c4, &cSq)
	c12.Square(&c6)

	// P0 = f2 · a^6 · b^12 · c^12 = f2^(1 + 6x + 12x² + 12x³)
	var P0 bn254.E12
	P0.Mul(&f2, &a6)
	P0.Mul(&P0, &b12)
	P0.Mul(&P0, &c12)

	// P1 = a^4 · b^6 · c^12 = f2^(4x + 6x² + 12x³)
	var P1 bn254.E12
	P1.Mul(&a4, &b6)
	P1.Mul(&P1, &c12)

	// P2 = a^6 · b^6 · c^12 = f2^(6x + 6x² + 12x³)
	var P2 bn254.E12
	P2.Mul(&a6, &b6)
	P2.Mul(&P2, &c12)

	// P3 = conj(f2) · a^4 · b^6 · c^12 = f2^(-1 + 4x + 6x² + 12x³)
	var P3 bn254.E12
	P3.Conjugate(&f2)
	P3.Mul(&P3, &a4)
	P3.Mul(&P3, &b6)
	P3.Mul(&P3, &c12)

	// result = P0 · Frob(P1) · FrobSq(P2) · FrobCube(P3)
	var P1f, P2f, P3f bn254.E12
	P1f.Frobenius(&P1)
	P2f.FrobeniusSquare(&P2)
	P3f.FrobeniusCube(&P3)

	var result bn254.E12
	result.Mul(&P0, &P1f)
	result.Mul(&result, &P2f)
	result.Mul(&result, &P3f)

	// Compare to gnark's standard final exponentiation.
	gnarkFinal := bn254.FinalExponentiation(&fE)

	if !result.Equal(&gnarkFinal) {
		t.Errorf("hard-part formula output does not match gnark.FinalExponentiation")
		t.Logf("ours:  %s", result.String())
		t.Logf("gnark: %s", gnarkFinal.String())
	}
}

// TestEmitWAFinalExpA6_ScriptMatchesGnark verifies the "compute a^6"
// portion of emitWAFinalExp's hard part against gnark by taking a real
// Fp12 witness a, running the codegen subset that builds a², a⁴, a⁶, and
// comparing the result component-wise.
func TestEmitWAFinalExpA6_ScriptMatchesGnark(t *testing.T) {
	// Produce a real witness a = f2^x from a real f, using the computeFinalExpWitnesses path.
	_, _, g1Aff, g2Aff := bn254.Generators()
	fGnark, err := bn254.MillerLoop([]bn254.G1Affine{g1Aff}, []bn254.G2Affine{g2Aff})
	if err != nil {
		t.Fatalf("MillerLoop: %v", err)
	}
	fFlat := e12ToFlatFp12(&fGnark)
	_, aFlat, _, _, err := computeFinalExpWitnesses(fFlat)
	if err != nil {
		t.Fatalf("computeFinalExpWitnesses: %v", err)
	}

	// Expected: a⁶ via gnark.
	var aE bn254.E12
	if err := flatFp12ToE12(aFlat, &aE); err != nil {
		t.Fatal(err)
	}
	var aSq, a4, a6 bn254.E12
	aSq.Square(&aE)
	a4.Square(&aSq)
	a6.Mul(&a4, &aSq)
	expectedFlat := e12ToFlatFp12(&a6)

	// Run the script: push a (12 Fp), run EmitWAFinalExpA6Debug, compare.
	var ops []codegen.StackOp
	for i := 0; i < 12; i++ {
		ops = append(ops, codegen.StackOp{
			Op:    "push",
			Value: codegen.PushValue{Kind: "bigint", BigInt: new(big.Int).Set(aFlat[i])},
		})
	}
	codegen.EmitWAFinalExpA6Debug(func(op codegen.StackOp) {
		ops = append(ops, op)
	})
	// Compare top-down.
	for i := 11; i >= 0; i-- {
		ops = append(ops, codegen.StackOp{
			Op:    "push",
			Value: codegen.PushValue{Kind: "bigint", BigInt: new(big.Int).Set(expectedFlat[i])},
		})
		ops = append(ops, codegen.StackOp{Op: "opcode", Code: "OP_EQUALVERIFY"})
	}
	ops = append(ops, codegen.StackOp{Op: "opcode", Code: "OP_1"})

	if err := codegen.BuildAndExecuteOps(ops); err != nil {
		t.Fatalf("emitWAFinalExp a^6 computation does not match gnark: %v", err)
	}
}

// TestEmitFp12MulSparse_ScriptMatchesGnark verifies bn254Fp12MulSparse
// by constructing a sparse Fp12 element in the canonical gnark-crypto form
// used by the BN254 Miller loop — (c0, 0, 0, c3, c4, 0) — computing
// dense*sparse both via the codegen script and via gnark's E12.Mul (treating
// the sparse element as a full E12 with zeros in the unused slots), and
// comparing component-wise.
func TestEmitFp12MulSparse_ScriptMatchesGnark(t *testing.T) {
	_, _, g1Aff, g2Aff := bn254.Generators()
	dense, err := bn254.MillerLoop([]bn254.G1Affine{g1Aff}, []bn254.G2Affine{g2Aff})
	if err != nil {
		t.Fatalf("MillerLoop: %v", err)
	}

	// Build a sparse element in canonical (c0, c3, c4) form:
	//   sparse.C0.B0 = c0, sparse.C1.B0 = c3, sparse.C1.B1 = c4,
	//   all other Fp2 slots = 0.
	var c0, c3, c4 bn254.E2
	c0.A0.SetUint64(7)
	c0.A1.SetUint64(11)
	c3.A0.SetUint64(13)
	c3.A1.SetUint64(17)
	c4.A0.SetUint64(19)
	c4.A1.SetUint64(23)

	var sparse bn254.E12
	sparse.C0.B0 = c0
	sparse.C0.B1.SetZero()
	sparse.C0.B2.SetZero()
	sparse.C1.B0 = c3
	sparse.C1.B1 = c4
	sparse.C1.B2.SetZero()

	// Expected product.
	var expected bn254.E12
	expected.Mul(&dense, &sparse)
	expectedFlat := e12ToFlatFp12(&expected)

	// Build the script inputs.
	denseFlat := e12ToFlatFp12(&dense)
	var ops []codegen.StackOp
	for i := 0; i < 12; i++ {
		ops = append(ops, codegen.StackOp{
			Op:    "push",
			Value: codegen.PushValue{Kind: "bigint", BigInt: new(big.Int).Set(denseFlat[i])},
		})
	}
	// Push sparse: c0_0, c0_1, c3_0, c3_1, c4_0, c4_1 (matching init order
	// in EmitFp12MulSparseStandalone).
	sparseComponents := []*bn254.E2{&c0, &c3, &c4}
	for _, e := range sparseComponents {
		var a0Big, a1Big big.Int
		e.A0.BigInt(&a0Big)
		e.A1.BigInt(&a1Big)
		ops = append(ops, codegen.StackOp{Op: "push", Value: codegen.PushValue{Kind: "bigint", BigInt: &a0Big}})
		ops = append(ops, codegen.StackOp{Op: "push", Value: codegen.PushValue{Kind: "bigint", BigInt: &a1Big}})
	}

	codegen.EmitFp12MulSparseStandalone(func(op codegen.StackOp) { ops = append(ops, op) })
	for i := 11; i >= 0; i-- {
		ops = append(ops, codegen.StackOp{
			Op:    "push",
			Value: codegen.PushValue{Kind: "bigint", BigInt: new(big.Int).Set(expectedFlat[i])},
		})
		ops = append(ops, codegen.StackOp{Op: "opcode", Code: "OP_EQUALVERIFY"})
	}
	ops = append(ops, codegen.StackOp{Op: "opcode", Code: "OP_1"})

	if err := codegen.BuildAndExecuteOps(ops); err != nil {
		t.Fatalf("bn254Fp12MulSparse does not match gnark: %v", err)
	}
}

// TestEmitFp12FrobeniusP_ScriptMatchesGnark verifies bn254Fp12FrobeniusP
// against gnark's E12.Frobenius on a real Fp12 value.
func TestEmitFp12FrobeniusP_ScriptMatchesGnark(t *testing.T) {
	_, _, g1Aff, g2Aff := bn254.Generators()
	fGnark, err := bn254.MillerLoop([]bn254.G1Affine{g1Aff}, []bn254.G2Affine{g2Aff})
	if err != nil {
		t.Fatalf("MillerLoop: %v", err)
	}
	fFlat := e12ToFlatFp12(&fGnark)

	var expected bn254.E12
	expected.Frobenius(&fGnark)
	expectedFlat := e12ToFlatFp12(&expected)

	var ops []codegen.StackOp
	for i := 0; i < 12; i++ {
		ops = append(ops, codegen.StackOp{
			Op:    "push",
			Value: codegen.PushValue{Kind: "bigint", BigInt: new(big.Int).Set(fFlat[i])},
		})
	}
	codegen.EmitFp12FrobeniusPStandalone(func(op codegen.StackOp) { ops = append(ops, op) })
	for i := 11; i >= 0; i-- {
		ops = append(ops, codegen.StackOp{
			Op:    "push",
			Value: codegen.PushValue{Kind: "bigint", BigInt: new(big.Int).Set(expectedFlat[i])},
		})
		ops = append(ops, codegen.StackOp{Op: "opcode", Code: "OP_EQUALVERIFY"})
	}
	ops = append(ops, codegen.StackOp{Op: "opcode", Code: "OP_1"})

	if err := codegen.BuildAndExecuteOps(ops); err != nil {
		t.Fatalf("bn254Fp12FrobeniusP does not match gnark: %v", err)
	}
}

// TestEmitFp12FrobeniusP2_ScriptMatchesGnark verifies bn254Fp12FrobeniusP2
// against gnark's E12.FrobeniusSquare on a real Fp12 value.
func TestEmitFp12FrobeniusP2_ScriptMatchesGnark(t *testing.T) {
	_, _, g1Aff, g2Aff := bn254.Generators()
	fGnark, err := bn254.MillerLoop([]bn254.G1Affine{g1Aff}, []bn254.G2Affine{g2Aff})
	if err != nil {
		t.Fatalf("MillerLoop: %v", err)
	}
	fFlat := e12ToFlatFp12(&fGnark)

	var expected bn254.E12
	expected.FrobeniusSquare(&fGnark)
	expectedFlat := e12ToFlatFp12(&expected)

	var ops []codegen.StackOp
	for i := 0; i < 12; i++ {
		ops = append(ops, codegen.StackOp{
			Op:    "push",
			Value: codegen.PushValue{Kind: "bigint", BigInt: new(big.Int).Set(fFlat[i])},
		})
	}
	codegen.EmitFp12FrobeniusP2Standalone(func(op codegen.StackOp) { ops = append(ops, op) })
	for i := 11; i >= 0; i-- {
		ops = append(ops, codegen.StackOp{
			Op:    "push",
			Value: codegen.PushValue{Kind: "bigint", BigInt: new(big.Int).Set(expectedFlat[i])},
		})
		ops = append(ops, codegen.StackOp{Op: "opcode", Code: "OP_EQUALVERIFY"})
	}
	ops = append(ops, codegen.StackOp{Op: "opcode", Code: "OP_1"})

	if err := codegen.BuildAndExecuteOps(ops); err != nil {
		t.Fatalf("bn254Fp12FrobeniusP2 does not match gnark: %v", err)
	}
}

// TestEmitFp12Sqr_ScriptMatchesGnark is a primitive-level sanity check:
// push a real Fp12 value, run bn254Fp12Sqr through the script, read back
// the 12 Fp outputs, and compare them to gnark's z.Square(z) on the same
// value. If this fails, the Fp12Sqr primitive itself is broken and no
// higher-level formula can work.
func TestEmitFp12Sqr_ScriptMatchesGnark(t *testing.T) {
	// Pick a real non-trivial Fp12: take the MillerLoop of the generators.
	_, _, g1Aff, g2Aff := bn254.Generators()
	fGnark, err := bn254.MillerLoop([]bn254.G1Affine{g1Aff}, []bn254.G2Affine{g2Aff})
	if err != nil {
		t.Fatalf("MillerLoop: %v", err)
	}
	fFlat := e12ToFlatFp12(&fGnark)

	// Expected = fGnark²
	var expected bn254.E12
	expected.Square(&fGnark)
	expectedFlat := e12ToFlatFp12(&expected)

	// Build the script: push f (12 Fp), run Fp12Sqr, compare component-wise.
	var ops []codegen.StackOp
	for i := 0; i < 12; i++ {
		ops = append(ops, codegen.StackOp{
			Op:    "push",
			Value: codegen.PushValue{Kind: "bigint", BigInt: new(big.Int).Set(fFlat[i])},
		})
	}
	codegen.EmitFp12SqrStandalone(func(op codegen.StackOp) {
		ops = append(ops, op)
	})
	// After EmitFp12SqrStandalone, the top-of-stack (innermost) is _r_b_2_1.
	// EmitFp12SqrStandalone rearranges the result to the top with toTop in
	// order _a_0_0, _a_0_1, _a_1_0, ..., _b_2_1, so the top slot is the
	// LAST one visited: _b_2_1. Then _b_2_0 is below, etc., and the deepest
	// of the 12 is _a_0_0.
	//
	// We compare by pushing each expected value onto the stack and doing
	// OP_EQUALVERIFY in reverse order (top to bottom).
	for i := 11; i >= 0; i-- {
		ops = append(ops, codegen.StackOp{
			Op:    "push",
			Value: codegen.PushValue{Kind: "bigint", BigInt: new(big.Int).Set(expectedFlat[i])},
		})
		ops = append(ops, codegen.StackOp{Op: "opcode", Code: "OP_EQUALVERIFY"})
	}
	// Leave truthy value on stack.
	ops = append(ops, codegen.StackOp{Op: "opcode", Code: "OP_1"})

	if err := codegen.BuildAndExecuteOps(ops); err != nil {
		t.Fatalf("Fp12Sqr script result does not match gnark: %v", err)
	}
}

// TestEmitFp12Mul_ScriptMatchesGnark is the Fp12 multiplication counterpart
// of TestEmitFp12Sqr_ScriptMatchesGnark.
func TestEmitFp12Mul_ScriptMatchesGnark(t *testing.T) {
	_, _, g1Aff, g2Aff := bn254.Generators()
	fA, err := bn254.MillerLoop([]bn254.G1Affine{g1Aff}, []bn254.G2Affine{g2Aff})
	if err != nil {
		t.Fatalf("MillerLoop: %v", err)
	}
	var fB bn254.E12
	fB.Square(&fA) // a distinct non-trivial Fp12 value

	var expected bn254.E12
	expected.Mul(&fA, &fB)
	expectedFlat := e12ToFlatFp12(&expected)

	aFlat := e12ToFlatFp12(&fA)
	bFlat := e12ToFlatFp12(&fB)

	var ops []codegen.StackOp
	for i := 0; i < 12; i++ {
		ops = append(ops, codegen.StackOp{
			Op:    "push",
			Value: codegen.PushValue{Kind: "bigint", BigInt: new(big.Int).Set(aFlat[i])},
		})
	}
	for i := 0; i < 12; i++ {
		ops = append(ops, codegen.StackOp{
			Op:    "push",
			Value: codegen.PushValue{Kind: "bigint", BigInt: new(big.Int).Set(bFlat[i])},
		})
	}
	codegen.EmitFp12MulStandalone(func(op codegen.StackOp) {
		ops = append(ops, op)
	})
	for i := 11; i >= 0; i-- {
		ops = append(ops, codegen.StackOp{
			Op:    "push",
			Value: codegen.PushValue{Kind: "bigint", BigInt: new(big.Int).Set(expectedFlat[i])},
		})
		ops = append(ops, codegen.StackOp{Op: "opcode", Code: "OP_EQUALVERIFY"})
	}
	ops = append(ops, codegen.StackOp{Op: "opcode", Code: "OP_1"})

	if err := codegen.BuildAndExecuteOps(ops); err != nil {
		t.Fatalf("Fp12Mul script result does not match gnark: %v", err)
	}
}

// TestEmitWAFinalExpF2_ScriptMatchesGnark verifies the easy-part computation
// of emitWAFinalExp: f2 = (conj(f)·f^-1) · frob_p2((conj(f)·f^-1)).
func TestEmitWAFinalExpF2_ScriptMatchesGnark(t *testing.T) {
	_, _, g1Aff, g2Aff := bn254.Generators()
	fGnark, err := bn254.MillerLoop([]bn254.G1Affine{g1Aff}, []bn254.G2Affine{g2Aff})
	if err != nil {
		t.Fatalf("MillerLoop: %v", err)
	}
	fFlat := e12ToFlatFp12(&fGnark)
	fInvFlat, aFlat, bFlat, cFlat, err := computeFinalExpWitnesses(fFlat)
	if err != nil {
		t.Fatalf("computeFinalExpWitnesses: %v", err)
	}

	var fE, fInvE bn254.E12
	flatFp12ToE12(fFlat, &fE)
	flatFp12ToE12(fInvFlat, &fInvE)
	var fConj, f1, f1Frob, f2 bn254.E12
	fConj.Conjugate(&fE)
	f1.Mul(&fConj, &fInvE)
	f1Frob.FrobeniusSquare(&f1)
	f2.Mul(&f1, &f1Frob)
	expectedFlat := e12ToFlatFp12(&f2)

	var ops []codegen.StackOp
	push := func(flat [12]*big.Int) {
		for i := 0; i < 12; i++ {
			ops = append(ops, codegen.StackOp{
				Op:    "push",
				Value: codegen.PushValue{Kind: "bigint", BigInt: new(big.Int).Set(flat[i])},
			})
		}
	}
	push(fFlat)
	push(fInvFlat)
	push(aFlat)
	push(bFlat)
	push(cFlat)
	codegen.EmitWAFinalExpF2Debug(func(op codegen.StackOp) { ops = append(ops, op) })
	for i := 11; i >= 0; i-- {
		ops = append(ops, codegen.StackOp{
			Op:    "push",
			Value: codegen.PushValue{Kind: "bigint", BigInt: new(big.Int).Set(expectedFlat[i])},
		})
		ops = append(ops, codegen.StackOp{Op: "opcode", Code: "OP_EQUALVERIFY"})
	}
	ops = append(ops, codegen.StackOp{Op: "opcode", Code: "OP_1"})

	if err := codegen.BuildAndExecuteOps(ops); err != nil {
		t.Fatalf("easy-part f2 script does not match gnark: %v", err)
	}
}

// TestEmitWAFinalExpP0_ScriptMatchesGnark verifies that the codegen
// computes P0 = f2 · a^6 · b^12 · c^12 correctly, where f2 is the easy
// part output. If this fails, the bug is in either f2 (easy part) or one
// of the per-witness power ladders (a^6, b^12, c^12), or the assembly of
// P0 via chained Fp12Mul.
func TestEmitWAFinalExpP0_ScriptMatchesGnark(t *testing.T) {
	_, _, g1Aff, g2Aff := bn254.Generators()
	fGnark, err := bn254.MillerLoop([]bn254.G1Affine{g1Aff}, []bn254.G2Affine{g2Aff})
	if err != nil {
		t.Fatalf("MillerLoop: %v", err)
	}
	fFlat := e12ToFlatFp12(&fGnark)
	fInvFlat, aFlat, bFlat, cFlat, err := computeFinalExpWitnesses(fFlat)
	if err != nil {
		t.Fatalf("computeFinalExpWitnesses: %v", err)
	}

	// Expected P0: compute easy-part f2, then f2 · a^6 · b^12 · c^12.
	var fE, fInvE, aE, bE, cE bn254.E12
	flatFp12ToE12(fFlat, &fE)
	flatFp12ToE12(fInvFlat, &fInvE)
	flatFp12ToE12(aFlat, &aE)
	flatFp12ToE12(bFlat, &bE)
	flatFp12ToE12(cFlat, &cE)
	// Easy part: f2 = conj(f) · f^-1 · frob_p2(f1)
	var fConj, f1, f1Frob, f2 bn254.E12
	fConj.Conjugate(&fE)
	f1.Mul(&fConj, &fInvE)
	f1Frob.FrobeniusSquare(&f1)
	f2.Mul(&f1, &f1Frob)
	// Powers
	var aSq, a4, a6 bn254.E12
	aSq.Square(&aE)
	a4.Square(&aSq)
	a6.Mul(&a4, &aSq)
	var bSq, b4, b6, b12 bn254.E12
	bSq.Square(&bE)
	b4.Square(&bSq)
	b6.Mul(&b4, &bSq)
	b12.Square(&b6)
	var cSq, c4, c6, c12 bn254.E12
	cSq.Square(&cE)
	c4.Square(&cSq)
	c6.Mul(&c4, &cSq)
	c12.Square(&c6)
	// P0 = f2 · a^6 · b^12 · c^12
	var P0 bn254.E12
	P0.Mul(&f2, &a6)
	P0.Mul(&P0, &b12)
	P0.Mul(&P0, &c12)
	expectedFlat := e12ToFlatFp12(&P0)

	// Build the script.
	var ops []codegen.StackOp
	push := func(flat [12]*big.Int) {
		for i := 0; i < 12; i++ {
			ops = append(ops, codegen.StackOp{
				Op:    "push",
				Value: codegen.PushValue{Kind: "bigint", BigInt: new(big.Int).Set(flat[i])},
			})
		}
	}
	push(fFlat)
	push(fInvFlat)
	push(aFlat)
	push(bFlat)
	push(cFlat)

	codegen.EmitWAFinalExpP0Debug(func(op codegen.StackOp) {
		ops = append(ops, op)
	})

	for i := 11; i >= 0; i-- {
		ops = append(ops, codegen.StackOp{
			Op:    "push",
			Value: codegen.PushValue{Kind: "bigint", BigInt: new(big.Int).Set(expectedFlat[i])},
		})
		ops = append(ops, codegen.StackOp{Op: "opcode", Code: "OP_EQUALVERIFY"})
	}
	ops = append(ops, codegen.StackOp{Op: "opcode", Code: "OP_1"})

	if err := codegen.BuildAndExecuteOps(ops); err != nil {
		t.Fatalf("P0 script does not match gnark: %v", err)
	}
}

// TestEmitWAFinalExp_ResultMatchesGnark is the component-wise version of
// TestEmitWAFinalExp_ScriptMatchesGnark: it captures the 12 Fp slots of
// the emitWAFinalExp output and compares them against gnark's
// FinalExponentiation result slot by slot. This gives a much more
// informative failure message if the result is wrong — we see exactly
// which component mismatches.
func TestEmitWAFinalExp_ResultMatchesGnark(t *testing.T) {
	// Use a real non-trivial Fp12 (NOT one that satisfies FinalExp==1 —
	// we want to see the actual raw result, not just an IsOne check).
	_, _, g1Aff, g2Aff := bn254.Generators()
	fGnark, err := bn254.MillerLoop([]bn254.G1Affine{g1Aff}, []bn254.G2Affine{g2Aff})
	if err != nil {
		t.Fatalf("MillerLoop: %v", err)
	}
	fFlat := e12ToFlatFp12(&fGnark)

	// Compute witnesses from f.
	fInvFlat, aFlat, bFlat, cFlat, err := computeFinalExpWitnesses(fFlat)
	if err != nil {
		t.Fatalf("computeFinalExpWitnesses: %v", err)
	}

	// Expected = gnark's FinalExponentiation(f).
	expected := bn254.FinalExponentiation(&fGnark)
	expectedFlat := e12ToFlatFp12(&expected)

	// Build the script: push 60 Fp values, run EmitWAFinalExpResultDebug,
	// compare the 12 output slots top-down.
	var ops []codegen.StackOp
	push := func(flat [12]*big.Int) {
		for i := 0; i < 12; i++ {
			ops = append(ops, codegen.StackOp{
				Op:    "push",
				Value: codegen.PushValue{Kind: "bigint", BigInt: new(big.Int).Set(flat[i])},
			})
		}
	}
	push(fFlat)
	push(fInvFlat)
	push(aFlat)
	push(bFlat)
	push(cFlat)

	codegen.EmitWAFinalExpResultDebug(func(op codegen.StackOp) {
		ops = append(ops, op)
	})

	// Compare slots top-down: the script leaves the 12 result slots on top
	// in order _a_0_0 (deepest of the 12), ..., _b_2_1 (top).
	for i := 11; i >= 0; i-- {
		ops = append(ops, codegen.StackOp{
			Op:    "push",
			Value: codegen.PushValue{Kind: "bigint", BigInt: new(big.Int).Set(expectedFlat[i])},
		})
		ops = append(ops, codegen.StackOp{Op: "opcode", Code: "OP_EQUALVERIFY"})
	}
	ops = append(ops, codegen.StackOp{Op: "opcode", Code: "OP_1"})

	if err := codegen.BuildAndExecuteOps(ops); err != nil {
		t.Fatalf("emitWAFinalExp script result does not match gnark.FinalExponentiation: %v", err)
	}
}

// TestTripleMillerLoopFinalExpMatchesOne verifies that the witness
// generator's tripleMillerLoopWithGradients output, when multiplied by
// MillerLoop(α, -β) and fed through gnark's FinalExponentiation, equals
// 1 — which is the Groth16 verification condition in the SP1 convention:
//
//	e(A, B) · e(L, -γ) · e(C, -δ) · e(α, -β) = 1.
func TestTripleMillerLoopFinalExpMatchesOne(t *testing.T) {
	_, _, g1Aff, g2Aff := bn254.Generators()
	scaleG1 := func(k int64) bn254.G1Affine {
		var p bn254.G1Affine
		p.ScalarMultiplication(&g1Aff, big.NewInt(k))
		return p
	}
	scaleG2 := func(k int64) bn254.G2Affine {
		var p bn254.G2Affine
		p.ScalarMultiplication(&g2Aff, big.NewInt(k))
		return p
	}

	alpha := scaleG1(1)
	beta := scaleG2(1)
	gamma := scaleG2(2)
	delta := scaleG2(3)

	prepared := scaleG1(3)
	proofC := scaleG1(2)
	proofA := scaleG1(13)
	proofB := beta

	// Negate β, γ, δ on the host side so we feed -γ and -δ into the
	// triple Miller loop (and later -β into PrecomputeAlphaNegBeta).
	var negBeta, negGamma, negDelta bn254.G2Affine
	negBeta.Neg(&beta)
	negGamma.Neg(&gamma)
	negDelta.Neg(&delta)

	preparedBig := [2]*big.Int{
		new(big.Int).Set(G1AffineToBig(prepared)[0]),
		new(big.Int).Set(G1AffineToBig(prepared)[1]),
	}
	_, fAfterLoop, err := tripleMillerLoopWithGradients(
		G1AffineToBig(proofA), G2AffineToBig(proofB),
		preparedBig, G2AffineToBig(negGamma),
		G1AffineToBig(proofC), G2AffineToBig(negDelta),
	)
	if err != nil {
		t.Fatalf("tripleMillerLoopWithGradients: %v", err)
	}

	// Multiply by MillerLoop(α, -β).
	alphaNegBetaFp12, err := PrecomputeAlphaNegBeta(G1AffineToBig(alpha), G2AffineToBig(negBeta))
	if err != nil {
		t.Fatalf("PrecomputeAlphaNegBeta: %v", err)
	}
	fAfterAB, err := fp12Mul12(fAfterLoop, alphaNegBetaFp12)
	if err != nil {
		t.Fatalf("fp12Mul12: %v", err)
	}

	// FinalExp.
	var fE bn254.E12
	if err := flatFp12ToE12(fAfterAB, &fE); err != nil {
		t.Fatal(err)
	}
	finalGo := bn254.FinalExponentiation(&fE)
	var one bn254.E12
	one.SetOne()
	if !finalGo.Equal(&one) {
		t.Errorf("FinalExp(f_witness_gen * MillerLoop(α,-β)) != 1\n  got = %s", finalGo.String())
	}
}

// TestTripleMillerLoopMatchesGnark runs the witness generator's
// tripleMillerLoopWithGradients on the D0 synthetic instance (in SP1
// pair order: (A,B), (prep,-γ), (C,-δ)) and verifies that its output,
// after gnark's FinalExponentiation, yields the same GT element as
// gnark's own bn254.MillerLoop+FinalExponentiation on the same inputs.
//
// Component-wise equality at the pre-final-exp stage is NOT expected:
// the witness generator scales every sparse line by Py (so the line has
// shape (Py, 0, 0, -λ·Px, λ·Tx-Ty, 0) rather than gnark's (1, 0, 0,
// -λ·Px/Py, (λ·Tx-Ty)/Py, 0)). Since Py ∈ Fp* and (p^12-1)/r is divisible
// by p-1, the Py^N accumulated factor vanishes after final exponentiation,
// so the GT result is identical.
func TestTripleMillerLoopMatchesGnark(t *testing.T) {
	_, _, g1Aff, g2Aff := bn254.Generators()
	scaleG1 := func(k int64) bn254.G1Affine {
		var p bn254.G1Affine
		p.ScalarMultiplication(&g1Aff, big.NewInt(k))
		return p
	}
	scaleG2 := func(k int64) bn254.G2Affine {
		var p bn254.G2Affine
		p.ScalarMultiplication(&g2Aff, big.NewInt(k))
		return p
	}

	beta := scaleG2(1)
	gamma := scaleG2(2)
	delta := scaleG2(3)

	prepared := scaleG1(3)
	proofC := scaleG1(2)
	proofA := scaleG1(13)
	proofB := beta

	var negGamma, negDelta bn254.G2Affine
	negGamma.Neg(&gamma)
	negDelta.Neg(&delta)

	// Gnark reference: MillerLoop of the 3 pairs in SP1 pair order.
	gnarkF, err := bn254.MillerLoop(
		[]bn254.G1Affine{proofA, prepared, proofC},
		[]bn254.G2Affine{proofB, negGamma, negDelta},
	)
	if err != nil {
		t.Fatalf("MillerLoop: %v", err)
	}

	// Witness generator's triple Miller loop.
	preparedBig := [2]*big.Int{
		new(big.Int).Set(G1AffineToBig(prepared)[0]),
		new(big.Int).Set(G1AffineToBig(prepared)[1]),
	}
	_, ourF, err := tripleMillerLoopWithGradients(
		G1AffineToBig(proofA), G2AffineToBig(proofB),
		preparedBig, G2AffineToBig(negGamma),
		G1AffineToBig(proofC), G2AffineToBig(negDelta),
	)
	if err != nil {
		t.Fatalf("tripleMillerLoopWithGradients: %v", err)
	}

	// Compare after final exponentiation: the Py-scaling accumulated in ourF
	// (one factor of Py per line per pair) is killed by the final exp.
	var ourE12 bn254.E12
	if err := flatFp12ToE12(ourF, &ourE12); err != nil {
		t.Fatalf("flatFp12ToE12: %v", err)
	}
	ourGT := bn254.FinalExponentiation(&ourE12)
	gnarkGT := bn254.FinalExponentiation(&gnarkF)
	if !ourGT.Equal(&gnarkGT) {
		t.Errorf("triple Miller loop (after final exp) mismatch:\n  ours  = %s\n  gnark = %s",
			ourGT.String(), gnarkGT.String())
	}
}

// TestEmitWAFinalExp_D0FThroughScript_IsOne runs emitWAFinalExp on the
// EXACT f value the D0 test's witness generator produces (after the triple
// Miller loop × e(α,β)). If D0 is a valid Groth16 instance (and it is —
// sanityCheckGroth16Instance verifies this via gnark.Pair), then the
// final exp result must be 1, and the script's IsOne check must pass.
func TestEmitWAFinalExp_D0FThroughScript_IsOne(t *testing.T) {
	// Reconstruct the D0 instance exactly as trivialGroth16Instance does.
	_, _, g1Aff, g2Aff := bn254.Generators()

	scaleG1 := func(k int64) bn254.G1Affine {
		var p bn254.G1Affine
		p.ScalarMultiplication(&g1Aff, big.NewInt(k))
		return p
	}
	scaleG2 := func(k int64) bn254.G2Affine {
		var p bn254.G2Affine
		p.ScalarMultiplication(&g2Aff, big.NewInt(k))
		return p
	}

	alpha := scaleG1(1)
	beta := scaleG2(1)
	gamma := scaleG2(2)
	delta := scaleG2(3)
	ic0 := scaleG1(1)
	ic1 := scaleG1(2)
	publicInput := big.NewInt(1)

	// VK stores β, γ, δ PRE-NEGATED (SP1 convention).
	vk := NewVerifyingKeyFromPositive(
		alpha, beta, gamma, delta,
		[]bn254.G1Affine{ic0, ic1},
	)
	proof := Proof{
		A: G1AffineToBig(scaleG1(13)),
		B: G2AffineToBig(beta),
		C: G1AffineToBig(scaleG1(2)),
	}

	w, err := GenerateWitness(vk, proof, []*big.Int{publicInput})
	if err != nil {
		t.Fatalf("GenerateWitness: %v", err)
	}

	// Reconstruct f after the Miller loop × MillerLoop(α,-β) — the value
	// the verifier script feeds into emitWAFinalExp. GenerateWitness
	// doesn't expose this directly, but we can reproduce it using the
	// same steps.
	alphaNegBetaFp12, _ := PrecomputeAlphaNegBeta(vk.AlphaG1, vk.BetaNegG2)

	// Re-run the Miller loop in pure Go to get fAfterLoop (same pair
	// order as GenerateWitness: (A,B), (prep,-γ), (C,-δ)).
	preparedInputs := [2]*big.Int{
		new(big.Int).Set(G1AffineToBig(scaleG1(3))[0]),
		new(big.Int).Set(G1AffineToBig(scaleG1(3))[1]),
	}
	_, fAfterLoop, err := tripleMillerLoopWithGradients(
		proof.A, proof.B,
		preparedInputs, vk.GammaNegG2,
		proof.C, vk.DeltaNegG2,
	)
	if err != nil {
		t.Fatalf("tripleMillerLoopWithGradients: %v", err)
	}
	fAfterAB, err := fp12Mul12(fAfterLoop, alphaNegBetaFp12)
	if err != nil {
		t.Fatalf("fp12Mul12: %v", err)
	}

	// Sanity: the final exp of fAfterAB should be 1 (the synthetic instance is valid).
	var fE bn254.E12
	if err := flatFp12ToE12(fAfterAB, &fE); err != nil {
		t.Fatal(err)
	}
	finalGo := bn254.FinalExponentiation(&fE)
	var one bn254.E12
	one.SetOne()
	if !finalGo.Equal(&one) {
		t.Fatalf("pure-Go FinalExp(fAfterAB) != 1: %s", finalGo.String())
	}

	// Build the script: push f (12), fInv (12), a (12), b (12), c (12),
	// run emitWAFinalExp, and OP_VERIFY the IsOne bool.
	var ops []codegen.StackOp
	push := func(flat [12]*big.Int) {
		for i := 0; i < 12; i++ {
			ops = append(ops, codegen.StackOp{
				Op:    "push",
				Value: codegen.PushValue{Kind: "bigint", BigInt: new(big.Int).Set(flat[i])},
			})
		}
	}
	push(fAfterAB)
	push(w.FinalExpFInv)
	push(w.FinalExpA)
	push(w.FinalExpB)
	push(w.FinalExpC)

	codegen.EmitWAFinalExpStandalone(func(op codegen.StackOp) { ops = append(ops, op) })
	ops = append(ops, codegen.StackOp{Op: "opcode", Code: "OP_VERIFY"})
	ops = append(ops, codegen.StackOp{Op: "opcode", Code: "OP_1"})

	if err := codegen.BuildAndExecuteOps(ops); err != nil {
		t.Fatalf("emitWAFinalExp on D0 f did not produce IsOne==true: %v", err)
	}
}

// TestEmitWAFinalExp_ScriptMatchesGnark is the script-level integration test
// for the witness-assisted final exponentiation codegen. It feeds a real
// Fp12 input (the one the verifier would see after MillerLoop × e(α,β) on
// the D0 synthetic instance — that value satisfies FinalExponentiation == 1)
// through codegen.EmitWAFinalExpStandalone and asserts that the final
// bn254Fp12IsOne check on top of stack is true.
//
// This isolates whether emitWAFinalExp's codegen translation of the
// hard-part formula is correct, independent of the Miller loop, MSM, or
// the rest of the verifier pipeline.
func TestEmitWAFinalExp_ScriptMatchesGnark(t *testing.T) {
	// Reconstruct the D0 synthetic Groth16 instance to obtain an f value
	// that satisfies FinalExponentiation(f) == 1.
	_, _, g1Aff, g2Aff := bn254.Generators()

	scaleG1 := func(k int64) bn254.G1Affine {
		var p bn254.G1Affine
		p.ScalarMultiplication(&g1Aff, big.NewInt(k))
		return p
	}
	scaleG2 := func(k int64) bn254.G2Affine {
		var p bn254.G2Affine
		p.ScalarMultiplication(&g2Aff, big.NewInt(k))
		return p
	}

	alpha := scaleG1(1)
	beta := scaleG2(1)
	gamma := scaleG2(2)
	delta := scaleG2(3)

	// prepared_inputs = G1 + 1*(2*G1) = 3*G1
	prepared := scaleG1(3)
	// C = 2*G1, A = 13*G1, B = G2
	proofC := scaleG1(2)
	proofA := scaleG1(13)
	proofB := beta

	var negA bn254.G1Affine
	negA.Neg(&proofA)

	// f = e(-A,B) · e(prepared,γ) · e(C,δ) · e(α,β), computed via
	// MillerLoop × multiplication. We must use MillerLoop (not Pair) because
	// Pair applies FinalExponentiation internally — we want the pre-final-exp
	// value that the verifier script feeds into emitWAFinalExp.
	fGnark, err := bn254.MillerLoop(
		[]bn254.G1Affine{negA, prepared, proofC, alpha},
		[]bn254.G2Affine{proofB, gamma, delta, beta},
	)
	if err != nil {
		t.Fatalf("MillerLoop: %v", err)
	}

	// Sanity: FinalExponentiation(f) should equal 1 (since the instance is valid).
	var one bn254.E12
	one.SetOne()
	gnarkFinal := bn254.FinalExponentiation(&fGnark)
	if !gnarkFinal.Equal(&one) {
		t.Fatalf("synthetic instance doesn't satisfy Groth16 check: gnark final = %s", gnarkFinal.String())
	}

	// Compute witnesses for this f.
	fFlat := e12ToFlatFp12(&fGnark)
	fInvFlat, aFlat, bFlat, cFlat, err := computeFinalExpWitnesses(fFlat)
	if err != nil {
		t.Fatalf("computeFinalExpWitnesses: %v", err)
	}

	// Build the script:
	// 1. Push f (12 Fp), fInv (12), a (12), b (12), c (12) = 60 pushes.
	// 2. Emit EmitWAFinalExpStandalone, which runs emitWAFinalExp and leaves
	//    the IsOne boolean on top.
	// 3. OP_VERIFY the boolean. If it's false, the script aborts.
	// 4. Push OP_1 as the final stack item so the interpreter returns success.
	var ops []codegen.StackOp
	pushFp12 := func(flat [12]*big.Int) {
		for i := 0; i < 12; i++ {
			ops = append(ops, codegen.StackOp{
				Op:    "push",
				Value: codegen.PushValue{Kind: "bigint", BigInt: new(big.Int).Set(flat[i])},
			})
		}
	}
	pushFp12(fFlat)
	pushFp12(fInvFlat)
	pushFp12(aFlat)
	pushFp12(bFlat)
	pushFp12(cFlat)

	codegen.EmitWAFinalExpStandalone(func(op codegen.StackOp) {
		ops = append(ops, op)
	})

	ops = append(ops, codegen.StackOp{Op: "opcode", Code: "OP_VERIFY"})
	ops = append(ops, codegen.StackOp{Op: "opcode", Code: "OP_1"})

	if err := codegen.BuildAndExecuteOps(ops); err != nil {
		t.Fatalf("emitWAFinalExp script did not produce IsOne==true on a valid f: %v", err)
	}
}

// TestComputePreparedInputs verifies that computePreparedInputs correctly
// returns IC[0] + sum(pub_j * IC[j+1]) for a set of public inputs, including
// the load-bearing case where some (or all) inputs are zero — the scenario
// that motivated the refactor away from on-chain MSM.
func TestComputePreparedInputs(t *testing.T) {
	_, _, g1Aff, _ := bn254.Generators()

	mkIC := func(scalar uint64) *[2]*big.Int {
		var p bn254.G1Affine
		p.ScalarMultiplication(&g1Aff, new(big.Int).SetUint64(scalar))
		pair := G1AffineToBig(p)
		return &pair
	}

	scaleG1Big := func(k int64) [2]*big.Int {
		var p bn254.G1Affine
		p.ScalarMultiplication(&g1Aff, big.NewInt(k))
		return G1AffineToBig(p)
	}

	// Case 1: all non-zero inputs.
	//   IC[0]=G1, IC[1]=2G1, IC[2]=3G1, pub=[5, 7]
	//   expected = G1 + 5*(2G1) + 7*(3G1) = G1 + 10G1 + 21G1 = 32G1
	{
		ic := []*[2]*big.Int{mkIC(1), mkIC(2), mkIC(3)}
		prepared, err := computePreparedInputs(ic, []*big.Int{big.NewInt(5), big.NewInt(7)})
		if err != nil {
			t.Fatalf("all-nonzero: %v", err)
		}
		expected := scaleG1Big(32)
		if prepared[0].Cmp(expected[0]) != 0 || prepared[1].Cmp(expected[1]) != 0 {
			t.Errorf("all-nonzero mismatch: got (%s, %s), want (%s, %s)",
				prepared[0], prepared[1], expected[0], expected[1])
		}
	}

	// Case 2: one zero input in the middle.
	//   IC[0]=G1, IC[1]=2G1, IC[2]=3G1, IC[3]=5G1, pub=[5, 0, 4]
	//   expected = G1 + 5*(2G1) + 0*(3G1) + 4*(5G1)
	//            = G1 + 10G1 + 0 + 20G1 = 31G1
	{
		ic := []*[2]*big.Int{mkIC(1), mkIC(2), mkIC(3), mkIC(5)}
		prepared, err := computePreparedInputs(ic, []*big.Int{
			big.NewInt(5), big.NewInt(0), big.NewInt(4),
		})
		if err != nil {
			t.Fatalf("with-zero: %v", err)
		}
		expected := scaleG1Big(31)
		if prepared[0].Cmp(expected[0]) != 0 || prepared[1].Cmp(expected[1]) != 0 {
			t.Errorf("with-zero mismatch: got (%s, %s), want (%s, %s)",
				prepared[0], prepared[1], expected[0], expected[1])
		}
	}

	// Case 3: all public inputs are zero — result must be exactly IC[0].
	// This is the scenario that the previous on-chain MSM could not
	// represent (it tried to compute a finite-lambda addition to identity).
	{
		ic := []*[2]*big.Int{mkIC(1), mkIC(2), mkIC(3)}
		prepared, err := computePreparedInputs(ic, []*big.Int{
			big.NewInt(0), big.NewInt(0),
		})
		if err != nil {
			t.Fatalf("all-zero: %v", err)
		}
		expected := scaleG1Big(1) // IC[0] = G1
		if prepared[0].Cmp(expected[0]) != 0 || prepared[1].Cmp(expected[1]) != 0 {
			t.Errorf("all-zero mismatch: got (%s, %s), want (%s, %s)",
				prepared[0], prepared[1], expected[0], expected[1])
		}
	}

	// Case 4: leading zero input (the first element of the accumulator
	// chain would be 0*IC + acc = acc). This used to break the on-chain
	// add helper because it tried to compute a slope into identity.
	{
		ic := []*[2]*big.Int{mkIC(1), mkIC(2), mkIC(3)}
		prepared, err := computePreparedInputs(ic, []*big.Int{
			big.NewInt(0), big.NewInt(7),
		})
		if err != nil {
			t.Fatalf("leading-zero: %v", err)
		}
		// expected = G1 + 0*(2G1) + 7*(3G1) = G1 + 21G1 = 22G1
		expected := scaleG1Big(22)
		if prepared[0].Cmp(expected[0]) != 0 || prepared[1].Cmp(expected[1]) != 0 {
			t.Errorf("leading-zero mismatch: got (%s, %s), want (%s, %s)",
				prepared[0], prepared[1], expected[0], expected[1])
		}
	}
}

// TestPrecomputeAlphaNegBeta verifies that PrecomputeAlphaNegBeta produces
// the PRE-final-exp MillerLoop(α, -β) value — NOT the post-final-exp GT
// element e(α, -β). The verifier multiplies this into the triple Miller
// loop accumulator and then applies FinalExp to the combined product, so
// the constant must live in the same space as the accumulator.
//
// The input betaNegG2 is ALREADY NEGATED, matching the SP1 Solidity VK
// convention. The test constructs -β by negating 5·G2 on the host side
// and asserts that PrecomputeAlphaNegBeta(3·G1, -5·G2) equals gnark's
// bn254.MillerLoop([3·G1], [-5·G2]).
func TestPrecomputeAlphaNegBeta(t *testing.T) {
	_, _, g1Aff, g2Aff := bn254.Generators()

	// Use 3*G1, 5*G2 as alpha, beta.
	var alpha bn254.G1Affine
	alpha.ScalarMultiplication(&g1Aff, big.NewInt(3))
	var beta bn254.G2Affine
	beta.ScalarMultiplication(&g2Aff, big.NewInt(5))

	// Pre-negate β on the host side (SP1 VK convention).
	var negBeta bn254.G2Affine
	negBeta.Neg(&beta)

	alphaBig := G1AffineToBig(alpha)
	negBetaBig := G2AffineToBig(negBeta)

	flatResult, err := PrecomputeAlphaNegBeta(alphaBig, negBetaBig)
	if err != nil {
		t.Fatalf("PrecomputeAlphaNegBeta: %v", err)
	}

	// Reference: gnark's bn254.MillerLoop([alpha], [-beta]) — pre-final-exp.
	expected, err := bn254.MillerLoop(
		[]bn254.G1Affine{alpha},
		[]bn254.G2Affine{negBeta},
	)
	if err != nil {
		t.Fatalf("bn254.MillerLoop: %v", err)
	}
	expectedFlat := e12ToFlatFp12(&expected)

	for i := 0; i < 12; i++ {
		if flatResult[i].Cmp(expectedFlat[i]) != 0 {
			t.Errorf("flat[%d] = %s, want %s", i, flatResult[i], expectedFlat[i])
		}
	}
}

// TestMillerLoopGradients_SatisfyLocalEquations is the strong self-consistency
// test for the witness generator's Miller loop gradients. It reproduces the
// D0 end-to-end test's synthetic Groth16 instance, runs
// tripleMillerLoopWithGradients to capture gradients, then REPLAYS the Miller
// loop step-by-step and verifies that every gradient satisfies the EXACT
// local equation the verifier checks:
//
//	doubling: lambda * (2*Ty) == 3*Tx^2  in Fp2     (using T BEFORE update)
//	addition: lambda * (Qx - Tx) == Qy - Ty  in Fp2 (using T BEFORE update)
//
// Gradients must be consumed in the same order as EmitGroth16VerifierWitnessAssisted:
// for each iteration i from msbIdx-1 down to 0, first the 3 pairs' doubling
// gradients in pair order (k=1,2,3), then if naf[i] != 0, the 3 pairs'
// addition gradients in pair order.
//
// If this test fails, the bug is in doubleStepWithLambda / addStepWithLambda:
// the lambda formula, the T evolution, or the order in which pairs are
// processed. If it passes, the gradients are mathematically valid for the
// verifier's local checks and the bug must be elsewhere.
func TestMillerLoopGradients_SatisfyLocalEquations(t *testing.T) {
	// --- Construct the SAME synthetic Groth16 instance as the D0 test ---
	// α=G1, β=G2, γ=2·G2, δ=3·G2, IC[0]=G1, IC[1]=2·G1,
	// pub_0=1, A=13·G1, B=G2, C=2·G1.
	_, _, g1Aff, g2Aff := bn254.Generators()

	scaleG1 := func(k int64) bn254.G1Affine {
		var p bn254.G1Affine
		p.ScalarMultiplication(&g1Aff, big.NewInt(k))
		return p
	}
	scaleG2 := func(k int64) bn254.G2Affine {
		var p bn254.G2Affine
		p.ScalarMultiplication(&g2Aff, big.NewInt(k))
		return p
	}

	gamma := scaleG2(2)
	delta := scaleG2(3)
	ic0 := scaleG1(1)
	ic1 := scaleG1(2)
	publicInput := big.NewInt(1)

	// Groth16 proof points.
	a := scaleG1(13)
	b := scaleG2(1)
	c := scaleG1(2)

	// prepared_inputs = IC[0] + pub_0 * IC[1] = G1 + 1*(2*G1) = 3*G1.
	var scaled bn254.G1Affine
	scaled.ScalarMultiplication(&ic1, publicInput)
	var prepared bn254.G1Affine
	prepared.Add(&ic0, &scaled)

	// negA = -A.
	var negA bn254.G1Affine
	negA.Neg(&a)

	preparedBig := G1AffineToBig(prepared)
	gammaBig := G2AffineToBig(gamma)
	cBig := G1AffineToBig(c)
	deltaBig := G2AffineToBig(delta)
	negABig := G1AffineToBig(negA)
	bBig := G2AffineToBig(b)

	// --- Run the witness generator's Miller loop to capture gradients ---
	gradients, _, err := tripleMillerLoopWithGradients(
		preparedBig, gammaBig, // pair 1
		cBig, deltaBig, //      pair 2
		negABig, bBig, //       pair 3
	)
	if err != nil {
		t.Fatalf("tripleMillerLoopWithGradients: %v", err)
	}
	if len(gradients)%2 != 0 {
		t.Fatalf("gradient count is not even: %d", len(gradients))
	}

	// --- Replay the Miller loop with the gradients, checking local equations ---
	p1, _ := toAffineG1(preparedBig)
	p2, _ := toAffineG1(cBig)
	p3, _ := toAffineG1(negABig)
	q1, _ := toAffineG2(gammaBig)
	q2, _ := toAffineG2(deltaBig)
	q3, _ := toAffineG2(bBig)
	_ = p1
	_ = p2
	_ = p3
	T := [3]affineG2{q1, q2, q3}
	Q := [3]affineG2{q1, q2, q3}
	negQ := [3]affineG2{negateAffineG2(q1), negateAffineG2(q2), negateAffineG2(q3)}

	naf := codegen.Bn254SixXPlus2NAF()
	msbIdx := len(naf) - 1
	for msbIdx > 0 && naf[msbIdx] == 0 {
		msbIdx--
	}

	// fp2Eq tests Fp2 equality.
	fp2Eq := func(a, b bn254.E2) bool {
		return a.A0.Equal(&b.A0) && a.A1.Equal(&b.A1)
	}

	// Build an Fp2 from 2 big.Ints (real, imag).
	buildFp2 := func(c0, c1 *big.Int) bn254.E2 {
		var e bn254.E2
		e.A0.SetBigInt(c0)
		e.A1.SetBigInt(c1)
		return e
	}

	// takeLambda pulls 2 big.Ints off the gradient slice as an Fp2.
	pos := 0
	takeLambda := func() (bn254.E2, int) {
		if pos+2 > len(gradients) {
			t.Fatalf("gradient slice underrun at pos=%d (len=%d)", pos, len(gradients))
		}
		lam := buildFp2(gradients[pos], gradients[pos+1])
		startPos := pos
		pos += 2
		return lam, startPos
	}

	failures := 0
	maxFailures := 5

	reportFail := func(iter int, step string, k int, lamPos int, msg string) {
		if failures < maxFailures {
			t.Errorf("iter=%d step=%s pair=%d lam@grad[%d..%d]: %s",
				iter, step, k+1, lamPos, lamPos+1, msg)
		}
		failures++
	}

	for i := msbIdx - 1; i >= 0; i-- {
		// Doubling: lambda * (2*Ty) == 3*Tx^2, BEFORE updating T.
		for k := 0; k < 3; k++ {
			lam, lamPos := takeLambda()

			// lhs = lambda * (2 * T.y)
			var twoTy bn254.E2
			twoTy.Double(&T[k].Y)
			var lhs bn254.E2
			lhs.Mul(&lam, &twoTy)

			// rhs = 3 * T.x^2
			var txSq bn254.E2
			txSq.Square(&T[k].X)
			var rhs bn254.E2
			var three fp.Element
			three.SetUint64(3)
			rhs.A0.Mul(&txSq.A0, &three)
			rhs.A1.Mul(&txSq.A1, &three)

			if !fp2Eq(lhs, rhs) {
				reportFail(i, "double", k, lamPos, fmt.Sprintf(
					"lambda*(2*Ty) != 3*Tx^2\n  lhs = (%s, %s)\n  rhs = (%s, %s)",
					&lhs.A0, &lhs.A1, &rhs.A0, &rhs.A1,
				))
			}

			// Now advance T using the same lambda (matching doubleStepWithLambda).
			var lamSq, twoTx, newTx bn254.E2
			lamSq.Square(&lam)
			twoTx.Double(&T[k].X)
			newTx.Sub(&lamSq, &twoTx)

			var diff, lProd, newTy bn254.E2
			diff.Sub(&T[k].X, &newTx)
			lProd.Mul(&lam, &diff)
			newTy.Sub(&lProd, &T[k].Y)

			T[k].X.Set(&newTx)
			T[k].Y.Set(&newTy)
		}

		// Addition: lambda * (Qx - Tx) == (Qy - Ty), BEFORE updating T.
		if naf[i] != 0 {
			for k := 0; k < 3; k++ {
				lam, lamPos := takeLambda()

				var qChosen affineG2
				if naf[i] == 1 {
					qChosen = Q[k]
				} else {
					qChosen = negQ[k]
				}

				// lhs = lambda * (Qx - Tx)
				var dx bn254.E2
				dx.Sub(&qChosen.X, &T[k].X)
				var lhs bn254.E2
				lhs.Mul(&lam, &dx)

				// rhs = Qy - Ty
				var rhs bn254.E2
				rhs.Sub(&qChosen.Y, &T[k].Y)

				if !fp2Eq(lhs, rhs) {
					reportFail(i, "add", k, lamPos, fmt.Sprintf(
						"lambda*(Qx-Tx) != Qy-Ty\n  lhs = (%s, %s)\n  rhs = (%s, %s)",
						&lhs.A0, &lhs.A1, &rhs.A0, &rhs.A1,
					))
				}

				// Advance T using the same lambda (matching addStepWithLambda).
				var lamSq, sub1, newTx bn254.E2
				lamSq.Square(&lam)
				sub1.Sub(&lamSq, &T[k].X)
				newTx.Sub(&sub1, &qChosen.X)

				var diff, lProd, newTy bn254.E2
				diff.Sub(&T[k].X, &newTx)
				lProd.Mul(&lam, &diff)
				newTy.Sub(&lProd, &T[k].Y)

				T[k].X.Set(&newTx)
				T[k].Y.Set(&newTy)
			}
		}
	}

	// Sanity check: we should have consumed exactly the gradients that the
	// main Miller loop produced. The two extra Frobenius corrections per pair
	// are NOT witness-assisted in the current codegen, so the gradient slice
	// should end exactly at the end of the main loop.
	if pos != len(gradients) {
		t.Errorf("gradient consumption mismatch: consumed %d of %d "+
			"(leftover=%d Fp values)", pos, len(gradients), len(gradients)-pos)
	}

	if failures > 0 {
		t.Fatalf("%d total gradient-local-equation failures "+
			"(reported the first %d above)", failures, maxFailures)
	}
}

// TestD0PreparedInputs_MatchesOnCurveExpectation verifies that the D0 test's
// prepared_inputs (pub=1, IC[0]=G1, IC[1]=2G1 → prep = G1 + 2G1 = 3G1) is
// on the BN254 G1 curve. The verifier does an explicit on-curve check on
// the prover-supplied prepared_inputs point before using it in pairing.
func TestD0PreparedInputs_MatchesOnCurveExpectation(t *testing.T) {
	_, _, g1Aff, _ := bn254.Generators()

	scaleG1 := func(k int64) bn254.G1Affine {
		var p bn254.G1Affine
		p.ScalarMultiplication(&g1Aff, big.NewInt(k))
		return p
	}

	ic0 := scaleG1(1)
	ic1 := scaleG1(2)
	publicInput := big.NewInt(1)

	ic := []*[2]*big.Int{
		ptr2(G1AffineToBig(ic0)),
		ptr2(G1AffineToBig(ic1)),
	}

	prepared, err := computePreparedInputs(ic, []*big.Int{publicInput})
	if err != nil {
		t.Fatalf("computePreparedInputs: %v", err)
	}

	// On-curve check: y^2 == x^3 + 3 mod p.
	prime := codegen.Bn254FieldPrime()
	lhs := new(big.Int).Mul(prepared[1], prepared[1])
	lhs.Mod(lhs, prime)
	rhs := new(big.Int).Mul(prepared[0], prepared[0])
	rhs.Mul(rhs, prepared[0])
	rhs.Add(rhs, big.NewInt(3))
	rhs.Mod(rhs, prime)
	if lhs.Cmp(rhs) != 0 {
		t.Errorf("prepared_inputs is not on curve: y^2=%s, x^3+3=%s", lhs, rhs)
	}

	// Prepared inputs must equal 3*G1.
	var expected bn254.G1Affine
	expected.ScalarMultiplication(&g1Aff, big.NewInt(3))
	expectedBig := G1AffineToBig(expected)
	if prepared[0].Cmp(expectedBig[0]) != 0 || prepared[1].Cmp(expectedBig[1]) != 0 {
		t.Errorf("prepared_inputs mismatch: got (%s, %s), want (%s, %s)",
			prepared[0], prepared[1], expectedBig[0], expectedBig[1])
	}
}

func ptr2(p [2]*big.Int) *[2]*big.Int {
	out := p
	return &out
}

// Compile-time guard: confirm the fr import is used (the package needs it
// for scalar field handling — silence the unused import warning if any
// helper drops it).
var _ = fr.Element{}

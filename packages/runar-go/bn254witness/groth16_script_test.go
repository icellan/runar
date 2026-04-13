package bn254witness_test

// End-to-end Phase 1F test: feed a hand-constructed valid Groth16 proof
// through the witness generator and the witness-assisted verifier script
// via codegen.BuildAndExecuteOps. This is the critical go/no-go gate the
// implementation plan calls Phase 1F (D0).
//
// We don't need a real circuit-derived proof for this test — bilinearity
// of the pairing lets us hand-construct a "synthetic" but mathematically
// valid Groth16 verification instance. Standard Groth16 (Groth 2016):
//
//	e(A, B) = e(α, β) · e(L, γ) · e(C, δ)
//
// Instantiated with all points as positive scalar multiples of (G1, G2):
//
//	α = G1,  β = G2,  γ = 2·G2,  δ = 3·G2
//	IC[0] = G1, IC[1] = 2·G1
//	pub_0 = 1   →   L = prep = G1 + 1·(2·G1) = 3·G1
//	C = 2·G1
//	A = 13·G1,  B = G2
//
// Check in e(G1,G2) exponent space:
//
//	A·B = α·β + L·γ + C·δ
//	13·1 = 1·1 + 3·2 + 2·3
//	13   = 1 + 6 + 6 = 13  ✓
//
// The verifier's rearranged form (SP1 convention — negate β, γ, δ on
// the G2 side, keep A, B, L, C, α positive) becomes:
//
//	e(A, B) · e(L, -γ) · e(C, -δ) · e(α, -β) = 1
//	= e(G1,G2)^13 · e(G1,G2)^(-6) · e(G1,G2)^(-6) · e(G1,G2)^(-1)
//	= e(G1,G2)^(13 - 6 - 6 - 1)
//	= e(G1,G2)^0 = 1  ✓
//
// This constructs a valid Groth16 verification instance without needing
// a circuit + prover, isolating the math validation from the gnark
// frontend dependency.

import (
	"fmt"
	"math/big"
	"testing"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"

	"github.com/icellan/runar/compilers/go/codegen"
	"github.com/icellan/runar/packages/runar-go/bn254witness"
)

// trivialGroth16Instance constructs a valid standard Groth16 verification
// instance. Groth's 2016 equation:
//
//	e(A, B) = e(α, β) · e(L, γ) · e(C, δ)
//
// The verifier's rearranged form (SP1 convention — negate β, γ, δ on
// the G2 side, A, B, L, C, α stay positive):
//
//	e(A, B) · e(L, -γ) · e(C, -δ) · e(α, -β) = 1
//
// We instantiate with all points as positive scalar multiples of (G1, G2)
// so we can match exponents directly:
//
//	α=G1   β=G2   γ=2·G2   δ=3·G2
//	IC[0]=G1   IC[1]=2·G1
//	pub_0 = 1   →   L = prep = G1 + 1·(2·G1) = 3·G1
//	C = 2·G1
//	A = 13·G1   B = G2
//
// Check (in e(G1,G2) exponent space):
//
//	A·B + L·(-γ) + C·(-δ) + α·(-β)
//	= 13·1 - 3·2 - 2·3 - 1·1
//	= 13 - 6 - 6 - 1 = 0  ✓
//
// The VerifyingKey is built via bn254witness.NewVerifyingKeyFromPositive,
// which takes the POSITIVE α, β, γ, δ and negates β, γ, δ internally
// before storing them in BetaNegG2 / GammaNegG2 / DeltaNegG2.
func trivialGroth16Instance(t *testing.T) (bn254witness.VerifyingKey, bn254witness.Proof, []*big.Int) {
	t.Helper()
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

	alpha := scaleG1(1) // G1
	beta := scaleG2(1)  // G2
	gamma := scaleG2(2) // 2*G2
	delta := scaleG2(3) // 3*G2
	ic0 := scaleG1(1)   // G1
	ic1 := scaleG1(2)   // 2*G1
	publicInput := big.NewInt(1)

	// Proof: A = 13*G1, B = G2, C = 2*G1
	a := scaleG1(13)
	b := scaleG2(1)
	c := scaleG1(2)

	// Build the VK using the positive-inputs helper. It internally
	// negates β, γ, δ and stores them in BetaNegG2 / GammaNegG2 /
	// DeltaNegG2, matching the SP1 Solidity convention.
	vk := bn254witness.NewVerifyingKeyFromPositive(
		alpha, beta, gamma, delta,
		[]bn254.G1Affine{ic0, ic1},
	)
	proof := bn254witness.Proof{
		A: bn254witness.G1AffineToBig(a),
		B: bn254witness.G2AffineToBig(b),
		C: bn254witness.G1AffineToBig(c),
	}

	// Sanity-check the synthetic instance using gnark's high-level Pair so
	// we don't waste cycles running a 460KB script on a broken witness.
	if err := sanityCheckGroth16Instance(alpha, beta, gamma, delta, ic0, ic1, publicInput, a, b, c); err != nil {
		t.Fatalf("synthetic Groth16 instance is not valid: %v", err)
	}

	return vk, proof, []*big.Int{publicInput}
}

// sanityCheckGroth16Instance verifies the constructed proof satisfies the
// SP1-rearranged Groth16 equation in GT using gnark's bn254.Pair. If this
// fails, the synthetic construction itself is wrong and the on-chain test
// cannot possibly succeed.
//
// Equation (SP1 convention — negate β, γ, δ on the G2 side):
//
//	e(A, B) · e(prepared, -γ) · e(C, -δ) · e(α, -β) = 1
//
// The caller passes POSITIVE γ, δ, β — this function negates them
// internally before running gnark.Pair so the test setup reads naturally.
func sanityCheckGroth16Instance(
	alpha bn254.G1Affine, beta bn254.G2Affine,
	gamma bn254.G2Affine, delta bn254.G2Affine,
	ic0 bn254.G1Affine, ic1 bn254.G1Affine,
	pub *big.Int,
	a bn254.G1Affine, b bn254.G2Affine, c bn254.G1Affine,
) error {
	var prepared bn254.G1Affine
	{
		var scaled bn254.G1Affine
		scaled.ScalarMultiplication(&ic1, pub)
		prepared.Add(&ic0, &scaled)
	}

	var negBeta, negGamma, negDelta bn254.G2Affine
	negBeta.Neg(&beta)
	negGamma.Neg(&gamma)
	negDelta.Neg(&delta)

	gt, err := bn254.Pair(
		[]bn254.G1Affine{a, prepared, c, alpha},
		[]bn254.G2Affine{b, negGamma, negDelta, negBeta},
	)
	if err != nil {
		return err
	}

	var one bn254.E12
	one.SetOne()
	if !gt.Equal(&one) {
		return fmt.Errorf("e(A,B) * e(prep,-γ) * e(C,-δ) * e(α,-β) = %s, want 1", gt.String())
	}
	return nil
}

// TestGroth16WA_EndToEnd_TrivialProof_Script is the Phase 1F D0 gate.
// It exercises the full pipeline:
//
//  1. Construct a synthetic but valid Groth16 instance (sanity-checked
//     against gnark's high-level pairing).
//  2. Generate witnesses via bn254witness.GenerateWitness.
//  3. Build the witness-assisted verifier locking script via
//     codegen.EmitGroth16VerifierWitnessAssisted.
//  4. Concatenate witness pushes + verifier ops.
//  5. Execute through codegen.BuildAndExecuteOps (the go-sdk script VM).
//
// If this test passes, the witness-assisted verifier math is end-to-end
// correct on a real Bitcoin Script VM. If it fails, Phase 2 debugging
// runs until it passes.
func TestGroth16WA_EndToEnd_TrivialProof_Script(t *testing.T) {
	vk, proof, publicInputs := trivialGroth16Instance(t)

	// Compute witnesses (Miller gradients, final exp witnesses, MSM
	// witnesses, etc.) using gnark-crypto Fp/Fp2/Fp12 arithmetic.
	w, err := bn254witness.GenerateWitness(vk, proof, publicInputs)
	if err != nil {
		t.Fatalf("GenerateWitness: %v", err)
	}

	// Compute the precomputed MillerLoop(α, -β) Fp12 constant that gets
	// baked into the locking script via Groth16Config.AlphaNegBetaFp12.
	alphaNegBetaFp12, err := bn254witness.PrecomputeAlphaNegBeta(vk.AlphaG1, vk.BetaNegG2)
	if err != nil {
		t.Fatalf("PrecomputeAlphaNegBeta: %v", err)
	}

	// Build the codegen Groth16Config with the VK values. ModuloThreshold=0
	// forces immediate mod reduction after every field op. The production
	// value is 2048 (from the nChain paper), but the BSV script interpreter's
	// O(n²) big-int arithmetic makes the deferred-mod path prohibitively slow
	// for the ~462K-op verifier: stack values grow to ~2KB between reductions
	// and the interpreter stalls. With 0, the script is larger but values
	// stay at ~32 bytes and the interpreter runs in ~1s.
	//
	// Bug A (byte-level vs. residue-class comparison in
	// emitWitnessGradientVerifyFp2) has been fixed, so this is now purely an
	// interpreter-performance workaround, not a correctness workaround.
	// Real BSV node execution (which uses native big-int ops) does not have
	// the O(n²) stall and happily runs the threshold=2048 script.
	config := codegen.Groth16Config{
		ModuloThreshold:  0,
		AlphaNegBetaFp12: alphaNegBetaFp12,
		GammaNegG2:       vk.GammaNegG2,
		DeltaNegG2:       vk.DeltaNegG2,
	}

	// Generate the verifier StackOps.
	var verifierOps []codegen.StackOp
	codegen.EmitGroth16VerifierWitnessAssisted(func(op codegen.StackOp) {
		verifierOps = append(verifierOps, op)
	}, config)

	// Concatenate: witness pushes (deepest first) + verifier ops.
	var ops []codegen.StackOp
	ops = append(ops, w.ToStackOps()...)
	ops = append(ops, verifierOps...)

	// Log script size for visibility — useful when this is the first time
	// the witness-assisted verifier ever runs end-to-end.
	t.Logf("D0 test: witness ops=%d  verifier ops=%d  total ops=%d",
		len(w.ToStackOps()), len(verifierOps), len(ops))

	// Note: the verifier's last operation is OP_VERIFY (which aborts on
	// failure). The script leaves the deepest item (_q, the field prime,
	// a non-zero bigint) on the stack as a truthy result, which the
	// interpreter accepts as a successful execution.
	if err := codegen.BuildAndExecuteOps(ops); err != nil {
		t.Fatalf("Groth16 WA verifier failed end-to-end: %v", err)
	}
}

// TestGroth16WA_EndToEnd_TamperedProofA_Rejected verifies that flipping
// one byte in proof.A causes the verifier to reject (the on-curve check
// or the pairing check should fail).
func TestGroth16WA_EndToEnd_TamperedProofA_Rejected(t *testing.T) {
	vk, proof, publicInputs := trivialGroth16Instance(t)

	// Tamper: add 1 to proof.A.x (likely makes the point off-curve).
	tampered := proof
	tampered.A = [2]*big.Int{
		new(big.Int).Add(proof.A[0], big.NewInt(1)),
		new(big.Int).Set(proof.A[1]),
	}

	// GenerateWitness may succeed (witnesses don't validate proof shape)
	// or it may fail (the on-curve internal check inside MSM might catch
	// this). Either way is fine — we just need the OVERALL flow to reject.
	w, err := bn254witness.GenerateWitness(vk, tampered, publicInputs)
	if err != nil {
		t.Logf("GenerateWitness rejected tampered proof (good): %v", err)
		return
	}

	alphaNegBetaFp12, _ := bn254witness.PrecomputeAlphaNegBeta(vk.AlphaG1, vk.BetaNegG2)
	// ModuloThreshold=0: same performance reason as the main D0 test.
	config := codegen.Groth16Config{
		ModuloThreshold:  0,
		AlphaNegBetaFp12: alphaNegBetaFp12,
		GammaNegG2:       vk.GammaNegG2,
		DeltaNegG2:       vk.DeltaNegG2,
	}

	var verifierOps []codegen.StackOp
	codegen.EmitGroth16VerifierWitnessAssisted(func(op codegen.StackOp) {
		verifierOps = append(verifierOps, op)
	}, config)

	var ops []codegen.StackOp
	ops = append(ops, w.ToStackOps()...)
	ops = append(ops, verifierOps...)

	if err := codegen.BuildAndExecuteOps(ops); err == nil {
		t.Error("expected verifier to reject tampered proof, but it accepted")
	}
}

// TestGroth16WA_EndToEnd_TamperedGradient_Rejected verifies that flipping
// one Miller-loop gradient causes the verifier's Fp2 gradient check to
// fail at runtime.
func TestGroth16WA_EndToEnd_TamperedGradient_Rejected(t *testing.T) {
	vk, proof, publicInputs := trivialGroth16Instance(t)

	w, err := bn254witness.GenerateWitness(vk, proof, publicInputs)
	if err != nil {
		t.Fatalf("GenerateWitness: %v", err)
	}
	if len(w.MillerGradients) == 0 {
		t.Fatal("no gradients generated")
	}
	// Tamper: add 1 to the first gradient (this breaks lambda*denom == numer).
	w.MillerGradients[0] = new(big.Int).Add(w.MillerGradients[0], big.NewInt(1))

	alphaNegBetaFp12, _ := bn254witness.PrecomputeAlphaNegBeta(vk.AlphaG1, vk.BetaNegG2)
	// ModuloThreshold=0: same performance reason as the main D0 test.
	config := codegen.Groth16Config{
		ModuloThreshold:  0,
		AlphaNegBetaFp12: alphaNegBetaFp12,
		GammaNegG2:       vk.GammaNegG2,
		DeltaNegG2:       vk.DeltaNegG2,
	}

	var verifierOps []codegen.StackOp
	codegen.EmitGroth16VerifierWitnessAssisted(func(op codegen.StackOp) {
		verifierOps = append(verifierOps, op)
	}, config)

	var ops []codegen.StackOp
	ops = append(ops, w.ToStackOps()...)
	ops = append(ops, verifierOps...)

	if err := codegen.BuildAndExecuteOps(ops); err == nil {
		t.Error("expected verifier to reject tampered gradient, but it accepted")
	}
}

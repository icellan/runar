// BN254 Groth16 witness-assisted verifier codegen — generates a complete
// Groth16 verification locking script where the prover (spender) supplies
// intermediate computation values in the unlocking script and the locking
// script only VERIFIES them.
//
// Techniques from nChain paper (eprint 2024/1498):
//   1. Witness-assisted field inversion: prover supplies inverse, script checks a*b mod p == 1
//   2. Witness-assisted line gradients: prover supplies lambda, script checks lambda*(x2-x1) == y2-y1
//   3. Modulo threshold: defer mod reduction until intermediates exceed configurable byte size
//   4. Batched modulo: reduce multiple Fp_n components sharing a single q-fetch
//   5. q at stack bottom: store modulus at main stack bottom, fetch with OP_DEPTH OP_1SUB OP_PICK
//   6. Precomputed e(alpha,beta): hardcoded Fp12 constant in locking script
//   7. Triple Miller loop: 3 pairs processed simultaneously (4th precomputed)
//
// This is a separate module from the general-purpose bn254.go/bn254_ext.go/bn254_pairing.go.
// It generates a monolithic Groth16 verifier, not composable builtins.
package codegen

import (
	"fmt"
	"math/big"
)

// =========================================================================
// Configuration
// =========================================================================

// Groth16Config holds the verification key and parameters for generating
// a witness-assisted Groth16 verifier script.
//
// The VK field names include "Neg" to document that the values are stored
// PRE-NEGATED on the G2 side. This matches the SP1 Solidity Groth16
// verifier convention (gnark-generated Solidity contracts in sp1-sdk), and
// lets SP1 VKs be dropped into Rúnar contracts with zero transformation:
//
//	SP1 BETA_NEG_X_0  ->  config.BetaNegG2 not stored here (see below)
//	SP1 GAMMA_NEG_X_0 ->  config.GammaNegG2[0]  (real part of x, pre-negated)
//	SP1 GAMMA_NEG_X_1 ->  config.GammaNegG2[1]  (imag part of x, pre-negated)
//	... etc
//
// The verification equation used (matching SP1's rearrangement — negate
// β, γ, δ on the G2 side, use A, B, L, C, α positive):
//
//	e(A, B) · e(L, -γ) · e(C, -δ) · e(α, -β) = 1
//
// All pairings are between POSITIVE G1 points (A, L, C, α) and the
// PRE-NEGATED G2 points (B is positive from the proof, -γ/-δ/-β are
// from the VK). β is NOT stored directly — the verifier precomputes
// MillerLoop(α, -β) off-chain and hardcodes the 12-Fp Fp12 result as
// AlphaNegBetaFp12 (baking α and -β together).
//
// IMPORTANT — Fp2 coordinate ordering:
// Rúnar uses (real, imaginary) order for all Fp2 elements:
//
//	G2 point = [x0, x1, y0, y1] where x = x0 + x1*u, y = y0 + y1*u
//
// The SP1 Solidity verifier uses the same convention: its _0 suffix is
// the real (c0) component and _1 is the imaginary (c1 / "i" coefficient)
// component. No Fp2 swap is needed when reading SP1 VK constants into
// Rúnar — the pre-negated β, γ, δ values in the Solidity contract drop
// straight into AlphaNegBetaFp12 (after MillerLoop), GammaNegG2, and
// DeltaNegG2.
//
// If your VK comes from RAW gnark-crypto serialization (Marshal() /
// EIP-197 byte order), you MUST swap each Fp2 pair with
// Bn254G2FromGnark() before assigning. See gnark_convert.go helpers for
// typed Go values — those do not need a swap.
type Groth16Config struct {
	// ModuloThreshold: numbers are reduced when they exceed this many bytes.
	// Optimal: 2048 (from nChain paper). Trade-off: smaller = larger script, faster execution.
	ModuloThreshold int

	// Precomputed MillerLoop(α, -β) as 12 Fp values in gnark flat order.
	// This is a PRE-final-exponentiation value. The verifier multiplies
	// the triple Miller loop accumulator by this, then applies a single
	// final exponentiation at the end.
	//
	// Coefficient order matches Gnark's flat Fp12 layout:
	//   [C0.B0.A0, C0.B0.A1, C0.B1.A0, C0.B1.A1, C0.B2.A0, C0.B2.A1,
	//    C1.B0.A0, C1.B0.A1, C1.B1.A0, C1.B1.A1, C1.B2.A0, C1.B2.A1]
	AlphaNegBetaFp12 [12]*big.Int

	// VK G2 points, PRE-NEGATED, in Rúnar (real, imag) order:
	//   [x_real, x_imag, y_real, y_imag]
	// The stored values are -γ and -δ (not γ and δ), matching the SP1
	// Solidity verifier's BETA_NEG / GAMMA_NEG / DELTA_NEG naming.
	GammaNegG2 [4]*big.Int // -γ
	DeltaNegG2 [4]*big.Int // -δ

	// NOTE: IC is optional. When nil (the default), the prover computes
	// prepared_inputs = IC[0] + sum(pub_j * IC[j+1]) off-chain and supplies
	// it as a single G1 witness point. The on-chain verifier does a single
	// on-curve check on that point and consumes it as the P for pair 2.
	//
	// This "raw" path is fast to verify but does NOT bind the prover's
	// prepared_inputs to specific public-input values — a hostile prover
	// could supply any on-curve G1 point along with a matching proof. It is
	// sound when the prover is trusted (e.g. SP1's Groth16 wrapper) and the
	// verifier relies on the pairing check alone to discriminate proofs.
	//
	// When IC is non-nil, EmitGroth16VerifierWitnessAssistedWithMSM emits a
	// stronger preamble that accepts 5 SP1 public-input scalars from the
	// witness stack, computes the MSM on-chain, and asserts the result
	// equals the prover-supplied prepared_inputs. This closes the hostile-
	// prover hole by binding the public-inputs to specific domain values
	// (typically a pinned SP1 program VK hash) visible to the method body.
	//
	// IC[i] = (IC[i][0], IC[i][1]) is a G1 point in Rúnar [x, y] order.
	IC [6][2]*big.Int
}

// DefaultGroth16Config returns a Groth16Config with sensible defaults for testing.
// All VK values are set to zero/identity — this is for script generation and
// size measurement, not for producing a valid proof check.
func DefaultGroth16Config() Groth16Config {
	cfg := Groth16Config{
		ModuloThreshold: 2048,
	}

	// Default AlphaNegBetaFp12 = 1 in Fp12 (1,0,0,...,0)
	for i := 0; i < 12; i++ {
		cfg.AlphaNegBetaFp12[i] = big.NewInt(0)
	}
	cfg.AlphaNegBetaFp12[0] = big.NewInt(1)

	// Default -gamma, -delta G2 = (0,0,0,0)
	for i := 0; i < 4; i++ {
		cfg.GammaNegG2[i] = big.NewInt(0)
		cfg.DeltaNegG2[i] = big.NewInt(0)
	}

	// Default IC = all zero points. The MSM variant requires non-zero IC
	// points supplied by the VK; the raw variant ignores IC.
	for i := 0; i < 6; i++ {
		cfg.IC[i] = [2]*big.Int{big.NewInt(0), big.NewInt(0)}
	}

	return cfg
}

// Groth16ConfigFromGnark constructs a Groth16Config from Gnark-SERIALIZED
// VK values (EIP-197 / Solidity ABI byte order for G2 points). All G2
// points are converted from Gnark's (imaginary, real) serialization order
// to Rúnar's (real, imaginary) order.
//
// The caller is expected to have ALREADY PRE-NEGATED the β, γ, δ G2
// values on the host side (matching SP1 Solidity convention), and to
// have passed MillerLoop(α, -β) as alphaNegBetaFp12. This helper is
// therefore labeled "FromGnark" but is really "FromSP1Style": the inputs
// are raw bytes in Gnark serialization, semantically pre-negated.
//
// The IC array is NOT part of Groth16Config — it is used only by the
// witness generator to compute prepared_inputs off-chain. See
// bn254witness.VerifyingKey.
//
// Parameters:
//   - alphaNegBetaFp12: precomputed MillerLoop(α, -β) as 12 Fp values in
//     Gnark's flat Fp12 order (no reordering needed for Fp12).
//   - gammaNegG2Gnark: -γ G2 in Gnark serialized order [x_im, x_re, y_im, y_re].
//   - deltaNegG2Gnark: -δ G2 in Gnark serialized order [x_im, x_re, y_im, y_re].
func Groth16ConfigFromGnark(
	alphaNegBetaFp12 [12]*big.Int,
	gammaNegG2Gnark [4]*big.Int,
	deltaNegG2Gnark [4]*big.Int,
) Groth16Config {
	cfg := Groth16Config{
		ModuloThreshold:  2048,
		AlphaNegBetaFp12: alphaNegBetaFp12,
		GammaNegG2:       swapFp2Pairs(gammaNegG2Gnark),
		DeltaNegG2:       swapFp2Pairs(deltaNegG2Gnark),
	}
	// IC is left zero — callers that need the MSM-binding variant must
	// populate Groth16Config.IC separately (it is not part of the gnark
	// serialized VK format and must be loaded via the SP1 VK loader).
	for i := 0; i < 6; i++ {
		cfg.IC[i] = [2]*big.Int{big.NewInt(0), big.NewInt(0)}
	}
	return cfg
}

// swapFp2Pairs converts [im, re, im, re] → [re, im, re, im].
func swapFp2Pairs(gnark [4]*big.Int) [4]*big.Int {
	return [4]*big.Int{gnark[1], gnark[0], gnark[3], gnark[2]}
}

// =========================================================================
// Witness-assisted primitives
// =========================================================================

// emitWitnessInverseVerify generates script that verifies a witness-supplied
// field inverse. The prover provides both `a` and `a_inv` in the unlocking
// script; the locking script verifies a * a_inv mod p == 1.
//
// This replaces the expensive a^(p-2) computation (~16 KB in script) with
// a simple mul + mod + comparison (~50 bytes).
//
// Stack effect (combined unlock + lock view):
//   Unlock pushes: [a, a_inv]
//   Lock script: verifies a * a_inv mod p == 1
//
// After: a_inv remains on stack as the verified result (a is consumed).
func emitWitnessInverseVerify(t *BN254Tracker, aName, aInvName, resultName string) {
	// Compute product = a * a_inv mod p
	t.copyToTop(aName, "_wiv_a")
	t.copyToTop(aInvName, "_wiv_ainv")
	bn254FieldMul(t, "_wiv_a", "_wiv_ainv", "_wiv_prod")

	// Check product == 1
	t.pushInt("_wiv_one", 1)
	t.toTop("_wiv_prod")
	t.toTop("_wiv_one")
	// OP_EQUALVERIFY consumes both items and pushes nothing (or aborts)
	t.rawBlock([]string{"_wiv_prod", "_wiv_one"}, "", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_EQUALVERIFY"})
	})

	// Drop the consumed a, keep a_inv as result
	t.toTop(aName)
	t.drop()
	t.toTop(aInvName)
	t.rename(resultName)
}

// emitWitnessGradientVerifyFp generates script that verifies a witness-supplied
// gradient (slope) in Fp. The prover provides lambda; the locking script
// verifies lambda * denom == numer (mod p).
//
// This replaces computing numer / denom (which needs a field inverse ~16 KB)
// with a simple mul + comparison (~50 bytes).
//
// All three inputs (lambda, denom, numer) must already be on the tracker.
// After verification, lambda remains as the verified result; denom and numer
// are consumed.
func emitWitnessGradientVerifyFp(t *BN254Tracker, lambdaName, denomName, numerName, resultName string) {
	// Compute lambda * denom mod p
	t.copyToTop(lambdaName, "_wgv_lam")
	t.copyToTop(denomName, "_wgv_den")
	bn254FieldMul(t, "_wgv_lam", "_wgv_den", "_wgv_prod")

	// Check product == numer
	t.toTop("_wgv_prod")
	t.toTop(numerName)
	t.rawBlock([]string{"_wgv_prod", numerName}, "", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_EQUALVERIFY"})
	})

	// Clean up denom, keep lambda as result
	t.toTop(denomName)
	t.drop()
	t.toTop(lambdaName)
	t.rename(resultName)
}

// emitWitnessGradientVerifyFp2 generates script that verifies a witness-supplied
// gradient (slope) in Fp2. The prover provides lambda = (l0, l1); the locking
// script verifies lambda * denom == numer in Fp2.
//
// All inputs must be on tracker: lambda (2 slots), denom (2 slots), numer (2 slots).
// After verification, lambda remains as result; denom and numer are consumed.
//
// IMPORTANT (qAtBottom + modThreshold): Under the witness-assisted verifier's
// tracker settings (SetQAtBottom + modThreshold > 0), bn254Fp2Mul is routed
// through the flat emitter which defers mod reductions while intermediates
// remain below the byte threshold. The raw Fp2 product in that mode is
// therefore unreduced multi-precision bytes — while the numerator coming from
// upstream MulConst/Sub may be reduced mod p. OP_EQUALVERIFY compares byte
// encodings, not residue classes, so we must explicitly bn254FieldMod both
// sides before the comparison.
func emitWitnessGradientVerifyFp2(t *BN254Tracker, lamPrefix, denomPrefix, numerPrefix, resultPrefix string) {
	// Compute lambda * denom in Fp2
	t.copyToTop(lamPrefix+"_0", "_wgv2_l0")
	t.copyToTop(lamPrefix+"_1", "_wgv2_l1")
	t.copyToTop(denomPrefix+"_0", "_wgv2_d0")
	t.copyToTop(denomPrefix+"_1", "_wgv2_d1")
	bn254Fp2Mul(t, "_wgv2_l0", "_wgv2_l1", "_wgv2_d0", "_wgv2_d1", "_wgv2_r0", "_wgv2_r1")

	// Reduce both sides mod p to canonical [0, p-1] representation before
	// the byte-level OP_EQUALVERIFY. Applying bn254FieldMod to an already
	// reduced value is idempotent, so it is safe for the numerator too.
	bn254FieldMod(t, "_wgv2_r0", "_wgv2_r0_red")
	bn254FieldMod(t, "_wgv2_r1", "_wgv2_r1_red")
	bn254FieldMod(t, numerPrefix+"_0", "_wgv2_n0_red")
	bn254FieldMod(t, numerPrefix+"_1", "_wgv2_n1_red")

	// Check r0_red == numer_0_red
	t.toTop("_wgv2_r0_red")
	t.toTop("_wgv2_n0_red")
	t.rawBlock([]string{"_wgv2_r0_red", "_wgv2_n0_red"}, "", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_EQUALVERIFY"})
	})

	// Check r1_red == numer_1_red
	t.toTop("_wgv2_r1_red")
	t.toTop("_wgv2_n1_red")
	t.rawBlock([]string{"_wgv2_r1_red", "_wgv2_n1_red"}, "", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_EQUALVERIFY"})
	})

	// Clean up any remaining denom slots (the numer slots were consumed by
	// bn254FieldMod above — no explicit drop needed for them).
	t.toTop(denomPrefix + "_0")
	t.drop()
	t.toTop(denomPrefix + "_1")
	t.drop()
	t.toTop(lamPrefix + "_0")
	t.rename(resultPrefix + "_0")
	t.toTop(lamPrefix + "_1")
	t.rename(resultPrefix + "_1")
}

// emitWitnessInverseVerifyFp12 generates script that verifies a witness-supplied
// Fp12 inverse. The prover provides both f (12 Fp values) and f_inv (12 Fp values);
// the locking script verifies f * f_inv == 1 in Fp12.
//
// This replaces the extremely expensive Fp12 inverse (~200 KB in script) with
// one Fp12 mul + 12 equality checks (~2 KB).
func emitWitnessInverseVerifyFp12(t *BN254Tracker, fPrefix, fInvPrefix, resultPrefix string) {
	// Compute product = f * f_inv in Fp12
	bn254Fp12CopyPrefix(t, fPrefix, "_wif12_f")
	bn254Fp12CopyPrefix(t, fInvPrefix, "_wif12_finv")
	bn254Fp12Mul(t, "_wif12_f", "_wif12_finv", "_wif12_prod")

	// Check product == 1 in Fp12 (first component 1, rest 0)
	bn254Fp12IsOne(t, "_wif12_prod", "_wif12_check")
	t.toTop("_wif12_check")
	t.rawBlock([]string{"_wif12_check"}, "", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_VERIFY"})
	})

	// Drop f, keep f_inv as result
	bn254Fp12DropInputs(t, fPrefix)
	bn254Fp12RenamePrefix(t, fInvPrefix, resultPrefix)
}

// =========================================================================
// Witness-assisted G1 point addition in Fp
// =========================================================================

// emitWAG1OnCurveCheck verifies that a witness-supplied G1 point (x, y) is on
// the BN254 curve: y^2 == x^3 + 3 mod p. The point remains on the tracker
// after verification (it is NOT consumed).
//
// Script checks: y*y mod p == (x*x*x + 3) mod p, aborts if false.
func emitWAG1OnCurveCheck(t *BN254Tracker, xName, yName string) {
	pfx := "_occhk_" + uniqueSuffixForOCC(xName, yName) + "_"

	// lhs = y^2 mod p
	t.copyToTop(yName, pfx+"y")
	bn254FieldSqr(t, pfx+"y", pfx+"lhs")

	// rhs = x^3 + 3 mod p
	t.copyToTop(xName, pfx+"xc")
	bn254FieldSqr(t, pfx+"xc", pfx+"x2")
	t.copyToTop(xName, pfx+"xc2")
	bn254FieldMul(t, pfx+"x2", pfx+"xc2", pfx+"x3")
	t.pushInt(pfx+"three", 3)
	bn254FieldAdd(t, pfx+"x3", pfx+"three", pfx+"rhs")

	// Check lhs == rhs
	t.toTop(pfx + "lhs")
	t.toTop(pfx + "rhs")
	t.rawBlock([]string{pfx + "lhs", pfx + "rhs"}, "", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_EQUALVERIFY"})
	})
}

// uniqueSuffixForOCC returns a short suffix so emitWAG1OnCurveCheck can be
// called multiple times within the same preamble without tracker name
// collisions on the `_occhk_*` temporary slots.
func uniqueSuffixForOCC(xName, yName string) string {
	// Combine the last few characters of each name; this is sufficient to
	// disambiguate the expected call sites (_pi_*, proof_a*, proof_c*).
	suf := ""
	if len(xName) > 0 {
		suf += string(xName[len(xName)-1])
	}
	if len(yName) > 0 {
		suf += string(yName[len(yName)-1])
	}
	// Additionally hash in a few more chars to avoid collisions when two
	// pairs share last letters (e.g. _pi_x/_pi_y vs proof_ax/proof_ay).
	if len(xName) > 2 {
		suf += string(xName[len(xName)-3])
	}
	return suf
}

// ===========================================================================
// Witness-assisted G2 point validation
// ===========================================================================
//
// BN254 twist curve E'(Fp2): y^2 = x^3 + b' where b' = 3/(9+u).
//
// Simplification:
//   3/(9+u) = 3*(9-u) / ((9+u)(9-u)) = 3*(9-u)/82
//          = (27 - 3u)/82
//          = 27*inv(82) - 3*inv(82)*u
// All arithmetic is mod p (the BN254 field prime).

// bn254TwistB0 and bn254TwistB1 are the two Fp components of b' = 3/(9+u).
// Computed at init time from the BN254 field prime.
var (
	bn254TwistB0 *big.Int // real part: 27 * inv(82) mod p
	bn254TwistB1 *big.Int // imag part: -3 * inv(82) mod p = (p - 3 * inv(82)) mod p
)

func init() {
	// inv(82) mod p via Fermat: 82^(p-2) mod p
	inv82 := new(big.Int).Exp(big.NewInt(82), bn254FieldPMinus2, bn254FieldP)
	bn254TwistB0 = new(big.Int).Mul(big.NewInt(27), inv82)
	bn254TwistB0.Mod(bn254TwistB0, bn254FieldP)
	bn254TwistB1 = new(big.Int).Mul(big.NewInt(3), inv82)
	bn254TwistB1.Neg(bn254TwistB1)
	bn254TwistB1.Mod(bn254TwistB1, bn254FieldP)
}

// emitWAG2OnCurveCheck verifies that a witness-supplied G2 point
// (x = x0 + x1*u, y = y0 + y1*u) is on the BN254 twist curve:
//
//	y^2 == x^3 + b'     (in Fp2)
//
// where b' = 3/(9+u). The point's four Fp coordinates remain on the tracker
// after verification (they are NOT consumed) — subsequent Miller-loop setup
// reads them via copyToTop.
//
// Aborts the script via OP_EQUALVERIFY if the relation does not hold.
// Cost: four Fp2 muls, one Fp2 add, two Fp2 equality checks — ~100 StackOps.
func emitWAG2OnCurveCheck(t *BN254Tracker, x0, x1, y0, y1 string) {
	pfx := "_g2occ_" + uniqueSuffixForOCC(x0, y1) + "_"

	// lhs = y^2  in Fp2 (preserve y0, y1: copy inputs first)
	t.copyToTop(y0, pfx+"y0")
	t.copyToTop(y1, pfx+"y1")
	bn254Fp2Sqr(t, pfx+"y0", pfx+"y1", pfx+"lhs_0", pfx+"lhs_1")

	// x2 = x^2  in Fp2 (preserve x0, x1)
	t.copyToTop(x0, pfx+"x0a")
	t.copyToTop(x1, pfx+"x1a")
	bn254Fp2Sqr(t, pfx+"x0a", pfx+"x1a", pfx+"x2_0", pfx+"x2_1")

	// x3 = x2 * x  in Fp2 (preserve x0, x1)
	t.copyToTop(x0, pfx+"x0b")
	t.copyToTop(x1, pfx+"x1b")
	bn254Fp2Mul(t, pfx+"x2_0", pfx+"x2_1", pfx+"x0b", pfx+"x1b", pfx+"x3_0", pfx+"x3_1")

	// rhs = x^3 + b'  in Fp2
	t.pushBigInt(pfx+"b0", bn254TwistB0)
	t.pushBigInt(pfx+"b1", bn254TwistB1)
	bn254Fp2Add(t, pfx+"x3_0", pfx+"x3_1", pfx+"b0", pfx+"b1", pfx+"rhs_0", pfx+"rhs_1")

	// Reduce both sides mod p for canonical byte-level OP_EQUALVERIFY. The
	// Fp2 arithmetic above may leave intermediates unreduced when the
	// tracker is in qAtBottom/threshold>0 mode, so apply bn254FieldMod.
	bn254FieldMod(t, pfx+"lhs_0", pfx+"lhs_0r")
	bn254FieldMod(t, pfx+"lhs_1", pfx+"lhs_1r")
	bn254FieldMod(t, pfx+"rhs_0", pfx+"rhs_0r")
	bn254FieldMod(t, pfx+"rhs_1", pfx+"rhs_1r")

	// Component-wise equality: abort if either fails.
	t.toTop(pfx + "lhs_0r")
	t.toTop(pfx + "rhs_0r")
	t.rawBlock([]string{pfx + "lhs_0r", pfx + "rhs_0r"}, "", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_EQUALVERIFY"})
	})
	t.toTop(pfx + "lhs_1r")
	t.toTop(pfx + "rhs_1r")
	t.rawBlock([]string{pfx + "lhs_1r", pfx + "rhs_1r"}, "", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_EQUALVERIFY"})
	})
}

// bn254SubgroupCheckScalar is the fixed scalar k = 6·x² for the BN254 twist
// endomorphism subgroup check, where x = 4965661367192848881 is the BN curve
// parameter. A G2 point P is in the prime-order subgroup G2 ⊂ E'(Fp²) iff
// ψ(P) == [k]·P, where ψ is the untwist-Frobenius-twist endomorphism
// (Scott, "Pairing-friendly curves"). The scalar is exactly 127 bits
// (0x6f4d884929dd7162 ...) and the locking script unrolls the bits of k at
// codegen time — doublings always, additions only at set bits.
var bn254SubgroupCheckScalar *big.Int

func init() {
	// x = 4965661367192848881 (BN254 seed, positive)
	x := new(big.Int).SetUint64(4965661367192848881)
	sq := new(big.Int).Mul(x, x)
	bn254SubgroupCheckScalar = new(big.Int).Mul(big.NewInt(6), sq)
}

// emitWAG2DoubleAffine performs witness-assisted doubling of a G2 point in
// affine coordinates. The prover supplies the tangent slope
//
//	λ = 3·Tx² / (2·Ty)          (in Fp2)
//
// under lamPrefix (2 Fp slots). The script verifies λ·(2·Ty) == 3·Tx² and
// then computes
//
//	Rx = λ² − 2·Tx
//	Ry = λ·(Tx − Rx) − Ty
//
// under rPrefix. T is consumed. If T happens to lie at 2-torsion (Ty = 0)
// the gradient check has no solution for λ (numerator 3·Tx² is nonzero
// unless Tx = 0 too, in which case T is already the identity and cannot
// have arisen from the curve equation with b' ≠ 0) — so the script aborts
// naturally, which is the correct behavior for subgroup testing.
func emitWAG2DoubleAffine(t *BN254Tracker, tPrefix, lamPrefix, rPrefix, uniqueSfx string) {
	pfx := "_wag2d" + uniqueSfx + "_"

	// --- Verify the witness gradient ---
	// Numerator: 3 · Tx² (Fp2)
	bn254Fp2SqrCopy(t, tPrefix+"_x", pfx+"txsq")
	bn254FieldMulConst(t, pfx+"txsq_0", 3, pfx+"lnum_0")
	bn254FieldMulConst(t, pfx+"txsq_1", 3, pfx+"lnum_1")

	// Denominator: 2 · Ty (Fp2)
	t.copyToTop(tPrefix+"_y_0", pfx+"ty0c")
	t.copyToTop(tPrefix+"_y_1", pfx+"ty1c")
	bn254FieldMulConst(t, pfx+"ty0c", 2, pfx+"lden_0")
	bn254FieldMulConst(t, pfx+"ty1c", 2, pfx+"lden_1")

	// Verify: λ · denom == numer in Fp2.
	emitWitnessGradientVerifyFp2(t, lamPrefix, pfx+"lden", pfx+"lnum", pfx+"lam")

	// --- Compute the doubled point ---
	// Rx = λ² − 2·Tx
	bn254Fp2SqrCopy(t, pfx+"lam", pfx+"lamsq")
	t.copyToTop(tPrefix+"_x_0", pfx+"tx0a")
	t.copyToTop(tPrefix+"_x_1", pfx+"tx1a")
	bn254FieldMulConst(t, pfx+"tx0a", 2, pfx+"2tx0")
	bn254FieldMulConst(t, pfx+"tx1a", 2, pfx+"2tx1")
	bn254Fp2Sub(t, pfx+"lamsq_0", pfx+"lamsq_1", pfx+"2tx0", pfx+"2tx1", rPrefix+"_x_0", rPrefix+"_x_1")

	// Ry = λ·(Tx − Rx) − Ty
	t.copyToTop(tPrefix+"_x_0", pfx+"txb0")
	t.copyToTop(tPrefix+"_x_1", pfx+"txb1")
	t.copyToTop(rPrefix+"_x_0", pfx+"rx0c")
	t.copyToTop(rPrefix+"_x_1", pfx+"rx1c")
	bn254Fp2Sub(t, pfx+"txb0", pfx+"txb1", pfx+"rx0c", pfx+"rx1c", pfx+"diff_0", pfx+"diff_1")
	t.copyToTop(pfx+"lam_0", pfx+"lamc0")
	t.copyToTop(pfx+"lam_1", pfx+"lamc1")
	bn254Fp2Mul(t, pfx+"lamc0", pfx+"lamc1", pfx+"diff_0", pfx+"diff_1", pfx+"lprod_0", pfx+"lprod_1")
	t.copyToTop(tPrefix+"_y_0", pfx+"ty0b")
	t.copyToTop(tPrefix+"_y_1", pfx+"ty1b")
	bn254Fp2Sub(t, pfx+"lprod_0", pfx+"lprod_1", pfx+"ty0b", pfx+"ty1b", rPrefix+"_y_0", rPrefix+"_y_1")

	// Clean up the verified λ and the now-consumed T.
	bn254DropNames(t, []string{pfx + "lam_0", pfx + "lam_1"})
	bn254DropNames(t, []string{tPrefix + "_x_0", tPrefix + "_x_1", tPrefix + "_y_0", tPrefix + "_y_1"})
}

// emitWAG2AddAffine performs witness-assisted addition of two distinct G2
// points T and Q in affine coordinates. The prover supplies the chord slope
//
//	λ = (Qy − Ty) / (Qx − Tx)   (in Fp2)
//
// under lamPrefix. The script verifies λ·(Qx − Tx) == (Qy − Ty), asserts
// Qx ≠ Tx (so the pseudo-addition cannot silently degenerate into
// doubling-by-infinity with an attacker-chosen λ), and computes
//
//	Rx = λ² − Tx − Qx
//	Ry = λ·(Tx − Rx) − Ty
//
// under rPrefix. Both T (4 slots) and the supplied Q COPY (4 slots) are
// consumed. If the Qx == Tx assertion fails (Qy == −Ty or Qy == Ty) the
// script aborts — the caller is responsible for not calling this helper
// when T and Q may collide, or for handling doubling separately.
func emitWAG2AddAffine(t *BN254Tracker, tPrefix, qPrefix, lamPrefix, rPrefix, uniqueSfx string) {
	pfx := "_wag2a" + uniqueSfx + "_"

	// --- Verify the witness gradient ---
	// Numerator: Qy − Ty
	t.copyToTop(qPrefix+"_y_0", pfx+"qy0")
	t.copyToTop(qPrefix+"_y_1", pfx+"qy1")
	t.copyToTop(tPrefix+"_y_0", pfx+"ty0")
	t.copyToTop(tPrefix+"_y_1", pfx+"ty1")
	bn254Fp2Sub(t, pfx+"qy0", pfx+"qy1", pfx+"ty0", pfx+"ty1", pfx+"ydf_0", pfx+"ydf_1")

	// Denominator: Qx − Tx
	t.copyToTop(qPrefix+"_x_0", pfx+"qx0")
	t.copyToTop(qPrefix+"_x_1", pfx+"qx1")
	t.copyToTop(tPrefix+"_x_0", pfx+"tx0")
	t.copyToTop(tPrefix+"_x_1", pfx+"tx1")
	bn254Fp2Sub(t, pfx+"qx0", pfx+"qx1", pfx+"tx0", pfx+"tx1", pfx+"xdf_0", pfx+"xdf_1")

	// Verify: λ · (Qx − Tx) == (Qy − Ty) in Fp2. This consumes the
	// numerator/denominator slots and leaves λ under pfx+"lam".
	emitWitnessGradientVerifyFp2(t, lamPrefix, pfx+"xdf", pfx+"ydf", pfx+"lam")

	// --- Compute the sum point ---
	// Rx = λ² − Tx − Qx
	bn254Fp2SqrCopy(t, pfx+"lam", pfx+"lamsq")
	t.copyToTop(tPrefix+"_x_0", pfx+"tx0a")
	t.copyToTop(tPrefix+"_x_1", pfx+"tx1a")
	bn254Fp2Sub(t, pfx+"lamsq_0", pfx+"lamsq_1", pfx+"tx0a", pfx+"tx1a", pfx+"sub1_0", pfx+"sub1_1")
	t.copyToTop(qPrefix+"_x_0", pfx+"qx0a")
	t.copyToTop(qPrefix+"_x_1", pfx+"qx1a")
	bn254Fp2Sub(t, pfx+"sub1_0", pfx+"sub1_1", pfx+"qx0a", pfx+"qx1a", rPrefix+"_x_0", rPrefix+"_x_1")

	// Ry = λ·(Tx − Rx) − Ty
	t.copyToTop(tPrefix+"_x_0", pfx+"txb0")
	t.copyToTop(tPrefix+"_x_1", pfx+"txb1")
	t.copyToTop(rPrefix+"_x_0", pfx+"rx0c")
	t.copyToTop(rPrefix+"_x_1", pfx+"rx1c")
	bn254Fp2Sub(t, pfx+"txb0", pfx+"txb1", pfx+"rx0c", pfx+"rx1c", pfx+"diff_0", pfx+"diff_1")
	t.copyToTop(pfx+"lam_0", pfx+"lamc0")
	t.copyToTop(pfx+"lam_1", pfx+"lamc1")
	bn254Fp2Mul(t, pfx+"lamc0", pfx+"lamc1", pfx+"diff_0", pfx+"diff_1", pfx+"lprod_0", pfx+"lprod_1")
	t.copyToTop(tPrefix+"_y_0", pfx+"ty0b")
	t.copyToTop(tPrefix+"_y_1", pfx+"ty1b")
	bn254Fp2Sub(t, pfx+"lprod_0", pfx+"lprod_1", pfx+"ty0b", pfx+"ty1b", rPrefix+"_y_0", rPrefix+"_y_1")

	// Clean up the verified λ, T, and the consumed Q copy.
	bn254DropNames(t, []string{pfx + "lam_0", pfx + "lam_1"})
	bn254DropNames(t, []string{tPrefix + "_x_0", tPrefix + "_x_1", tPrefix + "_y_0", tPrefix + "_y_1"})
	bn254DropNames(t, []string{qPrefix + "_x_0", qPrefix + "_x_1", qPrefix + "_y_0", qPrefix + "_y_1"})
}

// emitWAG2FixedScalarMul computes [k]·P on G2 in affine coordinates, where
// k is a fixed scalar known at codegen time. It unrolls left-to-right
// double-and-add over the bits of k: the MSB initialises the accumulator
// to P (so no gradient is needed for it), then each subsequent bit emits
// one doubling and, if set, one addition of the original P.
//
// The prover supplies witness gradients under gradientPrefix:
//
//   - Doublings: {gradientPrefix}_d_{i}_0, {gradientPrefix}_d_{i}_1 for
//     i in [0, numDoublings). Index 0 is the doubling that happens
//     IMMEDIATELY AFTER the MSB (i.e. for bit index msb-1).
//   - Additions: {gradientPrefix}_a_{j}_0, {gradientPrefix}_a_{j}_1 for
//     j counting set bits (excluding the MSB) from high to low.
//
// The input P must already be on the tracker as four Fp slots named
// basePrefix+"_x_0", basePrefix+"_x_1", basePrefix+"_y_0", basePrefix+"_y_1".
// P is NOT consumed — emitWAG2FixedScalarMul reads the coordinates via
// copyToTop so the caller can continue to use P afterwards (e.g. to
// compute ψ(P) for the subgroup equality). The result [k]·P is left
// under rPrefix+"_x_0", rPrefix+"_x_1", rPrefix+"_y_0", rPrefix+"_y_1".
//
// Soundness note: for a well-formed witness, each intermediate T_i has
// Ty ≠ 0 (since P ∈ G2 with r ∤ i · k for 0 < i ≤ k) and each addition
// step has Qx ≠ Tx (since i·P ≠ ±P for i ∈ (1, r)). For a forged P, the
// gradient check fails at the first 2-torsion or x-collision step (see
// helper docstrings above). The final equality with ψ(P) is the primary
// soundness gate.
func emitWAG2FixedScalarMul(t *BN254Tracker, basePrefix string, k *big.Int, gradientPrefix, rPrefix string) {
	if k.Sign() <= 0 {
		panic("emitWAG2FixedScalarMul: scalar must be positive")
	}
	nbits := k.BitLen()

	// Initialise accumulator T = P.
	t.copyToTop(basePrefix+"_x_0", "_sgm_T_x_0")
	t.copyToTop(basePrefix+"_x_1", "_sgm_T_x_1")
	t.copyToTop(basePrefix+"_y_0", "_sgm_T_y_0")
	t.copyToTop(basePrefix+"_y_1", "_sgm_T_y_1")

	doubleIdx := 0
	addIdx := 0

	// Iterate from bit (nbits-2) down to 0. The MSB (nbits-1) was consumed
	// by the initialisation above.
	for i := nbits - 2; i >= 0; i-- {
		// --- Doubling: T = 2T ---
		lamD := gradientPrefix + "_d_" + itoa(doubleIdx)
		emitWAG2DoubleAffine(t, "_sgm_T", lamD, "_sgm_Td", "d"+itoa(doubleIdx))
		// Rename _sgm_Td back to _sgm_T for the next iteration.
		t.toTop("_sgm_Td_x_0")
		t.rename("_sgm_T_x_0")
		t.toTop("_sgm_Td_x_1")
		t.rename("_sgm_T_x_1")
		t.toTop("_sgm_Td_y_0")
		t.rename("_sgm_T_y_0")
		t.toTop("_sgm_Td_y_1")
		t.rename("_sgm_T_y_1")
		doubleIdx++

		// --- Addition (only if this bit is set): T = T + P ---
		if k.Bit(i) == 1 {
			// Fresh copy of P under a disambiguated prefix so the add helper
			// can consume it.
			pcopy := "_sgm_Pc_" + itoa(addIdx)
			t.copyToTop(basePrefix+"_x_0", pcopy+"_x_0")
			t.copyToTop(basePrefix+"_x_1", pcopy+"_x_1")
			t.copyToTop(basePrefix+"_y_0", pcopy+"_y_0")
			t.copyToTop(basePrefix+"_y_1", pcopy+"_y_1")

			lamA := gradientPrefix + "_a_" + itoa(addIdx)
			emitWAG2AddAffine(t, "_sgm_T", pcopy, lamA, "_sgm_Ta", "a"+itoa(addIdx))
			// Rename _sgm_Ta back to _sgm_T.
			t.toTop("_sgm_Ta_x_0")
			t.rename("_sgm_T_x_0")
			t.toTop("_sgm_Ta_x_1")
			t.rename("_sgm_T_x_1")
			t.toTop("_sgm_Ta_y_0")
			t.rename("_sgm_T_y_0")
			t.toTop("_sgm_Ta_y_1")
			t.rename("_sgm_T_y_1")
			addIdx++
		}
	}

	// Rename the final accumulator to the caller-visible result.
	t.toTop("_sgm_T_x_0")
	t.rename(rPrefix + "_x_0")
	t.toTop("_sgm_T_x_1")
	t.rename(rPrefix + "_x_1")
	t.toTop("_sgm_T_y_0")
	t.rename(rPrefix + "_y_0")
	t.toTop("_sgm_T_y_1")
	t.rename(rPrefix + "_y_1")
}

// bn254SubgroupCheckGradientCount returns (numDoublings, numAdditions) for
// the fixed scalar k = 6·x² used by emitWAG2SubgroupCheck. Used by the
// witness-package side to allocate the right number of Fp2 gradients and by
// the main entry points to build initNames.
func bn254SubgroupCheckGradientCount() (numDoublings, numAdditions int) {
	k := bn254SubgroupCheckScalar
	nbits := k.BitLen()
	numDoublings = nbits - 1 // one per bit after the MSB
	numAdditions = 0
	for i := 0; i < nbits-1; i++ {
		if k.Bit(i) == 1 {
			numAdditions++
		}
	}
	return
}

// appendSubgroupGradientNames appends the tracker names for the G2
// subgroup-check gradients (see emitWAG2SubgroupCheck) in the order the
// unlocking script pushes them: all doublings first (index 0 first, i.e.
// deepest on the stack), then all additions. Each gradient is 2 Fp slots
// named "{prefix}_d_{i}_0", "{prefix}_d_{i}_1" for doublings and
// "{prefix}_a_{j}_0", "{prefix}_a_{j}_1" for additions, with prefix "_sgd".
// The pairing with the emit-side code lives in emitWAG2FixedScalarMul,
// which reads gradientPrefix + "_d_{i}" / "_a_{j}" names.
func appendSubgroupGradientNames(initNames []string) []string {
	nD, nA := bn254SubgroupCheckGradientCount()
	for i := 0; i < nD; i++ {
		initNames = append(initNames, "_sgd_d_"+itoa(i)+"_0")
		initNames = append(initNames, "_sgd_d_"+itoa(i)+"_1")
	}
	for j := 0; j < nA; j++ {
		initNames = append(initNames, "_sgd_a_"+itoa(j)+"_0")
		initNames = append(initNames, "_sgd_a_"+itoa(j)+"_1")
	}
	return initNames
}

// Bn254SubgroupCheckGradientCount is the exported alias of
// bn254SubgroupCheckGradientCount used by the witness package. Returns
// (numDoublings, numAdditions).
func Bn254SubgroupCheckGradientCount() (int, int) {
	return bn254SubgroupCheckGradientCount()
}

// Bn254SubgroupCheckScalar returns 6·x² (x = 4965661367192848881) as a
// fresh *big.Int — the fixed scalar the witness-assisted subgroup check
// raises proof.B to. Exported so the witness package can reuse it when
// computing the expected doubling/addition chain off-chain.
func Bn254SubgroupCheckScalar() *big.Int {
	return new(big.Int).Set(bn254SubgroupCheckScalar)
}

// emitWAG2SubgroupCheck verifies that a witness-supplied G2 point is in the
// prime-order subgroup G2 ⊂ E'(Fp²) by checking the BN-specific
// endomorphism relation
//
//	ψ(P) == [6·x²]·P             (Scott, "Pairing-friendly curves",
//	                               https://eprint.iacr.org/2021/1130 §8)
//
// where ψ is the untwist-Frobenius-twist map already available as
// bn254G2FrobeniusP, and x = 4965661367192848881 is the BN254 seed.
// The identity is a two-sided characterisation of G2 membership on BN
// curves: on the prime-order subgroup ψ acts as multiplication by p mod r
// = 6·x² (mod r), while on the non-trivial cofactor subgroups of E'(Fp²)
// it disagrees with [6·x²] — so a single equality check rules out every
// forgery vector documented in Barreto et al., "Subgroup security in
// pairing-based cryptography" (https://eprint.iacr.org/2015/247).
//
// Implementation: the scalar 6·x² is 127 bits with popcount 70, so
// left-to-right double-and-add expands to 126 doublings and 69 additions.
// Each step consumes one Fp² witness gradient supplied by the prover
// (390 Fp values in total). The on-chain verifier uses
// emitWitnessGradientVerifyFp2 on the prover's λ values — exactly the
// same primitive the Miller loop already uses for line gradients, so the
// soundness argument carries over: a witness-consistent λ is the unique
// tangent/chord slope at each step. ψ(P) is then computed deterministically
// via bn254G2FrobeniusP and the two 4-tuples compared component-wise.
//
// Cost: ~195 gradient verifications × (Fp2Mul + 2 FieldMod + 2 EqVerify) ≈
// 30 KB of script, inside the 20–40 KB budget the surrounding pairing
// preamble was allocated. The soundness argument is a straightforward
// appeal to the Scott / Housni & Fuentes-Castañeda BN characterisation —
// no new cryptographic assumption.
//
// The prover-supplied witness is read from the tracker under the
// gradient prefix "_sgd" with indices matching emitWAG2FixedScalarMul's
// layout:
//
//   - _sgd_d_{i}_0, _sgd_d_{i}_1 for i in [0, 126)
//   - _sgd_a_{j}_0, _sgd_a_{j}_1 for j in [0, 69)
//
// The four P coordinates (x0, x1, y0, y1) are NOT consumed by this
// function — they remain for the subsequent Miller-loop setup.
func emitWAG2SubgroupCheck(t *BN254Tracker, x0, x1, y0, y1 string) {
	pfx := "_g2sg_"

	// --- Compute ψ(P) from P. bn254G2FrobeniusP consumes its input
	// prefix's 4 slots, so work on a fresh copy to keep the originals
	// available for the main verifier pipeline (and for the scalar-mul
	// below, which reads basePrefix coordinates via copyToTop).
	t.copyToTop(x0, pfx+"psi_src_x_0")
	t.copyToTop(x1, pfx+"psi_src_x_1")
	t.copyToTop(y0, pfx+"psi_src_y_0")
	t.copyToTop(y1, pfx+"psi_src_y_1")
	bn254G2FrobeniusP(t, pfx+"psi_src", pfx+"psi")

	// --- Build a local copy of P under the basePrefix the scalar-mul
	// helper expects. We keep the originals intact for the Miller-loop
	// input; this local copy is read via copyToTop and dropped at the end.
	t.copyToTop(x0, pfx+"base_x_0")
	t.copyToTop(x1, pfx+"base_x_1")
	t.copyToTop(y0, pfx+"base_y_0")
	t.copyToTop(y1, pfx+"base_y_1")

	// --- Witness-assisted scalar-mul: S = [6·x²]·P. Gradients were pushed
	// by the unlocking script under the "_sgd" prefix.
	emitWAG2FixedScalarMul(t, pfx+"base", bn254SubgroupCheckScalar, "_sgd", pfx+"smul")

	// --- Drop the base-point copy now that the scalar-mul is done.
	bn254DropNames(t, []string{
		pfx + "base_x_0", pfx + "base_x_1",
		pfx + "base_y_0", pfx + "base_y_1",
	})

	// --- Canonicalise both sides mod p (the scalar-mul output may be
	// unreduced under qAtBottom + modThreshold > 0; ψ(P) is produced by
	// Fp2MulByFrobCoeff, which under the same mode can also return
	// unreduced multi-precision bytes).
	bn254FieldMod(t, pfx+"psi_x_0", pfx+"psi_x_0r")
	bn254FieldMod(t, pfx+"psi_x_1", pfx+"psi_x_1r")
	bn254FieldMod(t, pfx+"psi_y_0", pfx+"psi_y_0r")
	bn254FieldMod(t, pfx+"psi_y_1", pfx+"psi_y_1r")
	bn254FieldMod(t, pfx+"smul_x_0", pfx+"smul_x_0r")
	bn254FieldMod(t, pfx+"smul_x_1", pfx+"smul_x_1r")
	bn254FieldMod(t, pfx+"smul_y_0", pfx+"smul_y_0r")
	bn254FieldMod(t, pfx+"smul_y_1", pfx+"smul_y_1r")

	// --- Component-wise equality: ψ(P).x == S.x, ψ(P).y == S.y.
	for _, comp := range []string{"x_0", "x_1", "y_0", "y_1"} {
		t.toTop(pfx + "psi_" + comp + "r")
		t.toTop(pfx + "smul_" + comp + "r")
		t.rawBlock([]string{pfx + "psi_" + comp + "r", pfx + "smul_" + comp + "r"}, "", func(e func(StackOp)) {
			e(StackOp{Op: "opcode", Code: "OP_EQUALVERIFY"})
		})
	}
}

// emitWAG1AddFp performs witness-assisted G1 point addition in Fp.
// The prover supplies the gradient lambda in the unlocking script; the script
// verifies lambda * (x2 - x1) == (y2 - y1) mod p, then computes the sum point:
//   x3 = lambda^2 - x1 - x2
//   y3 = lambda * (x1 - x3) - y1
//
// Both input points are consumed; the result point is placed on the tracker.
func emitWAG1AddFp(t *BN254Tracker, p1xName, p1yName, p2xName, p2yName, lamName, resultXName, resultYName string) {
	pfx := "_wag1a_"

	// --- Verify the witness gradient ---
	// Numerator: y2 - y1
	t.copyToTop(p2yName, pfx+"y2")
	t.copyToTop(p1yName, pfx+"y1")
	bn254FieldSub(t, pfx+"y2", pfx+"y1", pfx+"numer")

	// Denominator: x2 - x1
	t.copyToTop(p2xName, pfx+"x2")
	t.copyToTop(p1xName, pfx+"x1")
	bn254FieldSub(t, pfx+"x2", pfx+"x1", pfx+"denom")

	// Verify: lambda * denom == numer in Fp
	emitWitnessGradientVerifyFp(t, lamName, pfx+"denom", pfx+"numer", pfx+"lam")

	// --- Use verified lambda to compute the sum point ---
	// x3 = lambda^2 - x1 - x2
	t.copyToTop(pfx+"lam", pfx+"lamc")
	bn254FieldSqr(t, pfx+"lamc", pfx+"lamsq")
	t.copyToTop(p1xName, pfx+"x1b")
	bn254FieldSub(t, pfx+"lamsq", pfx+"x1b", pfx+"sub1")
	t.copyToTop(p2xName, pfx+"x2b")
	bn254FieldSub(t, pfx+"sub1", pfx+"x2b", resultXName)

	// y3 = lambda * (x1 - x3) - y1
	t.copyToTop(p1xName, pfx+"x1c")
	t.copyToTop(resultXName, pfx+"x3c")
	bn254FieldSub(t, pfx+"x1c", pfx+"x3c", pfx+"diff")
	t.copyToTop(pfx+"lam", pfx+"lamd")
	bn254FieldMul(t, pfx+"lamd", pfx+"diff", pfx+"lprod")
	t.copyToTop(p1yName, pfx+"y1b")
	bn254FieldSub(t, pfx+"lprod", pfx+"y1b", resultYName)

	// Clean up lambda and input points
	bn254DropNames(t, []string{pfx + "lam"})
	bn254DropNames(t, []string{p1xName, p1yName, p2xName, p2yName})
}

// =========================================================================
// Witness-assisted line evaluation for Miller loop doubling step
// =========================================================================

// emitWALineEvalDoubleSparse computes the tangent line at T, evaluated at P,
// and doubles T. Instead of computing lambda = 3*Tx^2 / (2*Ty), the prover
// supplies lambda and the script verifies lambda * (2*Ty) == 3*Tx^2 in Fp2.
//
// The prover must push lambda (2 Fp values) in the unlocking script.
// lambda must already be on the tracker when this function is called.
//
// Saves ~15 KB per doubling step by eliminating the Fp2 inversion.
func emitWALineEvalDoubleSparse(t *BN254Tracker, tPrefix, lamPrefix, pxName, pyName, rTPrefix, linePrefix, uniqueSfx string) {
	pfx := "_waled" + uniqueSfx + "_"

	// --- Verify the witness gradient ---
	// Numerator: 3 * Tx^2
	bn254Fp2SqrCopy(t, tPrefix+"_x", pfx+"txsq")
	bn254FieldMulConst(t, pfx+"txsq_0", 3, pfx+"lnum_0")
	bn254FieldMulConst(t, pfx+"txsq_1", 3, pfx+"lnum_1")

	// Denominator: 2 * Ty
	t.copyToTop(tPrefix+"_y_0", pfx+"ty0c")
	t.copyToTop(tPrefix+"_y_1", pfx+"ty1c")
	bn254FieldMulConst(t, pfx+"ty0c", 2, pfx+"lden_0")
	bn254FieldMulConst(t, pfx+"ty1c", 2, pfx+"lden_1")

	// Verify: lambda * denom == numer in Fp2
	emitWitnessGradientVerifyFp2(t, lamPrefix, pfx+"lden", pfx+"lnum", pfx+"lam")

	// --- Use verified lambda to double T and compute line evaluation ---
	// (Same computation as bn254LineEvalDoubleSparse but using the verified lambda
	// instead of computing it from scratch)

	// Tx' = lambda^2 - 2*Tx
	bn254Fp2SqrCopy(t, pfx+"lam", pfx+"lamsq")
	t.copyToTop(tPrefix+"_x_0", pfx+"tx0a")
	t.copyToTop(tPrefix+"_x_1", pfx+"tx1a")
	bn254FieldMulConst(t, pfx+"tx0a", 2, pfx+"2tx0")
	bn254FieldMulConst(t, pfx+"tx1a", 2, pfx+"2tx1")
	bn254Fp2Sub(t, pfx+"lamsq_0", pfx+"lamsq_1", pfx+"2tx0", pfx+"2tx1", rTPrefix+"_x_0", rTPrefix+"_x_1")

	// Ty' = lambda*(Tx - Tx') - Ty
	t.copyToTop(tPrefix+"_x_0", pfx+"txb0")
	t.copyToTop(tPrefix+"_x_1", pfx+"txb1")
	t.copyToTop(rTPrefix+"_x_0", pfx+"ntx0")
	t.copyToTop(rTPrefix+"_x_1", pfx+"ntx1")
	bn254Fp2Sub(t, pfx+"txb0", pfx+"txb1", pfx+"ntx0", pfx+"ntx1", pfx+"diff_0", pfx+"diff_1")
	t.copyToTop(pfx+"lam_0", pfx+"lamc0")
	t.copyToTop(pfx+"lam_1", pfx+"lamc1")
	bn254Fp2Mul(t, pfx+"lamc0", pfx+"lamc1", pfx+"diff_0", pfx+"diff_1", pfx+"lprod_0", pfx+"lprod_1")
	t.copyToTop(tPrefix+"_y_0", pfx+"ty0b")
	t.copyToTop(tPrefix+"_y_1", pfx+"ty1b")
	bn254Fp2Sub(t, pfx+"lprod_0", pfx+"lprod_1", pfx+"ty0b", pfx+"ty1b", rTPrefix+"_y_0", rTPrefix+"_y_1")

	// Canonical gnark BN254 sparse line (affine, Py-scaled):
	//   c4 = lambda * Tx - Ty
	t.copyToTop(pfx+"lam_0", pfx+"lamd0")
	t.copyToTop(pfx+"lam_1", pfx+"lamd1")
	t.copyToTop(tPrefix+"_x_0", pfx+"txc0")
	t.copyToTop(tPrefix+"_x_1", pfx+"txc1")
	bn254Fp2Mul(t, pfx+"lamd0", pfx+"lamd1", pfx+"txc0", pfx+"txc1", pfx+"ltx_0", pfx+"ltx_1")
	t.copyToTop(tPrefix+"_y_0", pfx+"ty0c")
	t.copyToTop(tPrefix+"_y_1", pfx+"ty1c")
	bn254Fp2Sub(t, pfx+"ltx_0", pfx+"ltx_1", pfx+"ty0c", pfx+"ty1c", pfx+"c4out_0", pfx+"c4out_1")

	// c3 = -lambda * Px
	t.copyToTop(pfx+"lam_0", pfx+"lame0")
	t.copyToTop(pfx+"lam_1", pfx+"lame1")
	bn254Fp2Neg(t, pfx+"lame0", pfx+"lame1", pfx+"nlam_0", pfx+"nlam_1")
	t.copyToTop(pxName, pfx+"pxc")
	bn254FieldMul(t, pfx+"nlam_0", pfx+"pxc", pfx+"c3out_0")
	t.copyToTop(pxName, pfx+"pxc2")
	bn254FieldMul(t, pfx+"nlam_1", pfx+"pxc2", pfx+"c3out_1")

	// c0 = (Py, 0)
	t.copyToTop(pyName, pfx+"c0out_0")
	t.pushInt(pfx+"c0out_1", 0)

	// Store sparse line: c0 → C0.B0, c3 → C1.B0, c4 → C1.B1.
	t.toTop(pfx + "c0out_0")
	t.rename(linePrefix + "_c0_0")
	t.toTop(pfx + "c0out_1")
	t.rename(linePrefix + "_c0_1")
	t.toTop(pfx + "c3out_0")
	t.rename(linePrefix + "_c3_0")
	t.toTop(pfx + "c3out_1")
	t.rename(linePrefix + "_c3_1")
	t.toTop(pfx + "c4out_0")
	t.rename(linePrefix + "_c4_0")
	t.toTop(pfx + "c4out_1")
	t.rename(linePrefix + "_c4_1")

	// Clean up lambda and old T
	bn254DropNames(t, []string{pfx + "lam_0", pfx + "lam_1"})
	bn254DropNames(t, []string{tPrefix + "_x_0", tPrefix + "_x_1", tPrefix + "_y_0", tPrefix + "_y_1"})
}

// emitWALineEvalAddSparse computes the chord line through T and Q,
// evaluated at P, and computes T + Q. Instead of computing
// lambda = (Qy - Ty) / (Qx - Tx), the prover supplies lambda and the
// script verifies lambda * (Qx - Tx) == (Qy - Ty) in Fp2.
func emitWALineEvalAddSparse(t *BN254Tracker, tPrefix, qPrefix, lamPrefix, pxName, pyName, rTPrefix, linePrefix, uniqueSfx string) {
	pfx := "_walea" + uniqueSfx + "_"

	// --- Verify the witness gradient ---
	// Numerator: Qy - Ty
	t.copyToTop(qPrefix+"_y_0", pfx+"qy0")
	t.copyToTop(qPrefix+"_y_1", pfx+"qy1")
	t.copyToTop(tPrefix+"_y_0", pfx+"ty0")
	t.copyToTop(tPrefix+"_y_1", pfx+"ty1")
	bn254Fp2Sub(t, pfx+"qy0", pfx+"qy1", pfx+"ty0", pfx+"ty1", pfx+"ydf_0", pfx+"ydf_1")

	// Denominator: Qx - Tx
	t.copyToTop(qPrefix+"_x_0", pfx+"qx0")
	t.copyToTop(qPrefix+"_x_1", pfx+"qx1")
	t.copyToTop(tPrefix+"_x_0", pfx+"tx0")
	t.copyToTop(tPrefix+"_x_1", pfx+"tx1")
	bn254Fp2Sub(t, pfx+"qx0", pfx+"qx1", pfx+"tx0", pfx+"tx1", pfx+"xdf_0", pfx+"xdf_1")

	// Verify: lambda * denom == numer in Fp2
	emitWitnessGradientVerifyFp2(t, lamPrefix, pfx+"xdf", pfx+"ydf", pfx+"lam")

	// --- Use verified lambda ---
	// Tx' = lambda^2 - Tx - Qx
	bn254Fp2SqrCopy(t, pfx+"lam", pfx+"lamsq")
	t.copyToTop(tPrefix+"_x_0", pfx+"tx0a")
	t.copyToTop(tPrefix+"_x_1", pfx+"tx1a")
	bn254Fp2Sub(t, pfx+"lamsq_0", pfx+"lamsq_1", pfx+"tx0a", pfx+"tx1a", pfx+"sub1_0", pfx+"sub1_1")
	t.copyToTop(qPrefix+"_x_0", pfx+"qx0a")
	t.copyToTop(qPrefix+"_x_1", pfx+"qx1a")
	bn254Fp2Sub(t, pfx+"sub1_0", pfx+"sub1_1", pfx+"qx0a", pfx+"qx1a", rTPrefix+"_x_0", rTPrefix+"_x_1")

	// Ty' = lambda*(Tx - Tx') - Ty
	t.copyToTop(tPrefix+"_x_0", pfx+"txb0")
	t.copyToTop(tPrefix+"_x_1", pfx+"txb1")
	t.copyToTop(rTPrefix+"_x_0", pfx+"ntx0")
	t.copyToTop(rTPrefix+"_x_1", pfx+"ntx1")
	bn254Fp2Sub(t, pfx+"txb0", pfx+"txb1", pfx+"ntx0", pfx+"ntx1", pfx+"diff_0", pfx+"diff_1")
	t.copyToTop(pfx+"lam_0", pfx+"lamc0")
	t.copyToTop(pfx+"lam_1", pfx+"lamc1")
	bn254Fp2Mul(t, pfx+"lamc0", pfx+"lamc1", pfx+"diff_0", pfx+"diff_1", pfx+"lprod_0", pfx+"lprod_1")
	t.copyToTop(tPrefix+"_y_0", pfx+"tyb0")
	t.copyToTop(tPrefix+"_y_1", pfx+"tyb1")
	bn254Fp2Sub(t, pfx+"lprod_0", pfx+"lprod_1", pfx+"tyb0", pfx+"tyb1", rTPrefix+"_y_0", rTPrefix+"_y_1")

	// Canonical gnark BN254 sparse line (affine, Py-scaled):
	//   c4 = lambda * Tx - Ty
	t.copyToTop(pfx+"lam_0", pfx+"lamd0")
	t.copyToTop(pfx+"lam_1", pfx+"lamd1")
	t.copyToTop(tPrefix+"_x_0", pfx+"txc0")
	t.copyToTop(tPrefix+"_x_1", pfx+"txc1")
	bn254Fp2Mul(t, pfx+"lamd0", pfx+"lamd1", pfx+"txc0", pfx+"txc1", pfx+"ltx_0", pfx+"ltx_1")
	t.copyToTop(tPrefix+"_y_0", pfx+"tyc0")
	t.copyToTop(tPrefix+"_y_1", pfx+"tyc1")
	bn254Fp2Sub(t, pfx+"ltx_0", pfx+"ltx_1", pfx+"tyc0", pfx+"tyc1", pfx+"c4out_0", pfx+"c4out_1")

	// c3 = -lambda * Px
	t.copyToTop(pfx+"lam_0", pfx+"lame0")
	t.copyToTop(pfx+"lam_1", pfx+"lame1")
	bn254Fp2Neg(t, pfx+"lame0", pfx+"lame1", pfx+"nlam_0", pfx+"nlam_1")
	t.copyToTop(pxName, pfx+"pxc")
	bn254FieldMul(t, pfx+"nlam_0", pfx+"pxc", pfx+"c3out_0")
	t.copyToTop(pxName, pfx+"pxc2")
	bn254FieldMul(t, pfx+"nlam_1", pfx+"pxc2", pfx+"c3out_1")

	// c0 = (Py, 0)
	t.copyToTop(pyName, pfx+"c0out_0")
	t.pushInt(pfx+"c0out_1", 0)

	// Store sparse line: c0 → C0.B0, c3 → C1.B0, c4 → C1.B1.
	t.toTop(pfx + "c0out_0")
	t.rename(linePrefix + "_c0_0")
	t.toTop(pfx + "c0out_1")
	t.rename(linePrefix + "_c0_1")
	t.toTop(pfx + "c3out_0")
	t.rename(linePrefix + "_c3_0")
	t.toTop(pfx + "c3out_1")
	t.rename(linePrefix + "_c3_1")
	t.toTop(pfx + "c4out_0")
	t.rename(linePrefix + "_c4_0")
	t.toTop(pfx + "c4out_1")
	t.rename(linePrefix + "_c4_1")

	// Clean up
	bn254DropNames(t, []string{pfx + "lam_0", pfx + "lam_1"})
	bn254DropNames(t, []string{tPrefix + "_x_0", tPrefix + "_x_1", tPrefix + "_y_0", tPrefix + "_y_1"})
}

// =========================================================================
// Witness-assisted Miller loop (triple: 3 pairs simultaneously)
// =========================================================================

// emitWAMillerLoop3 computes the product of 3 Miller loops using
// witness-assisted gradients. For each doubling/addition step, the prover
// supplies the line gradient in the unlocking script and the locking script
// verifies it.
//
// The gradients must be pre-pushed onto the tracker with names:
//   "_wlam_d{k}_{iteration}" for doubling gradients (pair k, iteration i)
//   "_wlam_a{k}_{iteration}" for addition gradients
// where k = 1,2,3 and iteration counts down from msbIdx-1 to 0.
//
// This function is called from EmitGroth16VerifierWitnessAssisted to generate
// the Miller loop portion of the locking script.
func emitWAMillerLoop3(t *BN254Tracker) {
	naf := bn254SixXPlus2NAF
	msbIdx := len(naf) - 1
	for msbIdx > 0 && naf[msbIdx] == 0 {
		msbIdx--
	}

	// Initialize T_i = Q_i for each pair
	for k := 1; k <= 3; k++ {
		ks := string(rune('0' + k))
		qpfx := "q" + ks
		tpfx := "_T" + ks
		t.copyToTop(qpfx+"x0", tpfx+"_x_0")
		t.copyToTop(qpfx+"x1", tpfx+"_x_1")
		t.copyToTop(qpfx+"y0", tpfx+"_y_0")
		t.copyToTop(qpfx+"y1", tpfx+"_y_1")
	}

	// Initialize f = 1
	bn254Fp12SetOne(t, "_f")

	// Prepare -Q_i for NAF digit = -1
	for k := 1; k <= 3; k++ {
		ks := string(rune('0' + k))
		qpfx := "q" + ks
		t.copyToTop(qpfx+"x0", "_negQ"+ks+"_x_0")
		t.copyToTop(qpfx+"x1", "_negQ"+ks+"_x_1")
		t.copyToTop(qpfx+"y0", "_negQ"+ks+"_y_0")
		t.copyToTop(qpfx+"y1", "_negQ"+ks+"_y_1")
		bn254G2Negate(t, "_negQ"+ks, "_nQ"+ks)
	}

	iterNum := 0

	// Main Miller loop
	for i := msbIdx - 1; i >= 0; i-- {
		// SHARED: f = f^2
		bn254Fp12Sqr(t, "_f", "_f_sq")
		bn254Fp12RenamePrefix(t, "_f_sq", "_f")

		// Doubling step for all 3 pairs with witness-assisted gradients
		for k := 1; k <= 3; k++ {
			ks := string(rune('0' + k))
			tpfx := "_T" + ks
			ppfx := "p" + ks
			lamName := "_wlam_d" + ks + "_" + itoa(iterNum)

			emitWALineEvalDoubleSparse(t, tpfx, lamName, ppfx+"x", ppfx+"y",
				tpfx+"d", "_ld"+ks, "d"+ks+itoa(iterNum))
			bn254RenameG2(t, tpfx+"d", tpfx)

			bn254Fp12MulSparse(t, "_f", "_ld"+ks, "_f_dbl"+ks)
			bn254Fp12RenamePrefix(t, "_f_dbl"+ks, "_f")
		}

		// Addition step for non-zero NAF digits
		switch naf[i] {
		case 1:
			for k := 1; k <= 3; k++ {
				ks := string(rune('0' + k))
				tpfx := "_T" + ks
				ppfx := "p" + ks
				lamName := "_wlam_a" + ks + "_" + itoa(iterNum)

				t.copyToTop("q"+ks+"x0", "_addQ"+ks+"_x_0")
				t.copyToTop("q"+ks+"x1", "_addQ"+ks+"_x_1")
				t.copyToTop("q"+ks+"y0", "_addQ"+ks+"_y_0")
				t.copyToTop("q"+ks+"y1", "_addQ"+ks+"_y_1")
				emitWALineEvalAddSparse(t, tpfx, "_addQ"+ks, lamName, ppfx+"x", ppfx+"y",
					tpfx+"a", "_la"+ks, "a"+ks+itoa(iterNum))
				bn254RenameG2(t, tpfx+"a", tpfx)

				bn254Fp12MulSparse(t, "_f", "_la"+ks, "_f_add"+ks)
				bn254Fp12RenamePrefix(t, "_f_add"+ks, "_f")
			}
		case -1:
			for k := 1; k <= 3; k++ {
				ks := string(rune('0' + k))
				tpfx := "_T" + ks
				ppfx := "p" + ks
				lamName := "_wlam_a" + ks + "_" + itoa(iterNum)

				t.copyToTop("_nQ"+ks+"_x_0", "_subQ"+ks+"_x_0")
				t.copyToTop("_nQ"+ks+"_x_1", "_subQ"+ks+"_x_1")
				t.copyToTop("_nQ"+ks+"_y_0", "_subQ"+ks+"_y_0")
				t.copyToTop("_nQ"+ks+"_y_1", "_subQ"+ks+"_y_1")
				emitWALineEvalAddSparse(t, tpfx, "_subQ"+ks, lamName, ppfx+"x", ppfx+"y",
					tpfx+"s", "_ls"+ks, "s"+ks+itoa(iterNum))
				bn254RenameG2(t, tpfx+"s", tpfx)

				bn254Fp12MulSparse(t, "_f", "_ls"+ks, "_f_sub"+ks)
				bn254Fp12RenamePrefix(t, "_f_sub"+ks, "_f")
			}
		}

		iterNum++
	}

	// Clean up -Q_i
	for k := 1; k <= 3; k++ {
		ks := string(rune('0' + k))
		bn254DropNames(t, []string{"_nQ" + ks + "_x_0", "_nQ" + ks + "_x_1",
			"_nQ" + ks + "_y_0", "_nQ" + ks + "_y_1"})
	}

	// BN254 corrections: Q1_k = pi(Q_k), Q2_k = -pi^2(Q_k)
	// These correction lines use the standard sparse evaluation (not witness-assisted)
	// because there are only 2 correction steps per pair (6 total) — the savings
	// from witness-assisting them is negligible.
	for k := 1; k <= 3; k++ {
		ks := string(rune('0' + k))
		tpfx := "_T" + ks
		ppfx := "p" + ks

		// Q1_k = pi(Q_k)
		t.copyToTop("q"+ks+"x0", "_fQ"+ks+"_x_0")
		t.copyToTop("q"+ks+"x1", "_fQ"+ks+"_x_1")
		t.copyToTop("q"+ks+"y0", "_fQ"+ks+"_y_0")
		t.copyToTop("q"+ks+"y1", "_fQ"+ks+"_y_1")
		bn254G2FrobeniusP(t, "_fQ"+ks, "_Q1_"+ks)

		// Q2_k = -pi^2(Q_k)
		t.copyToTop("q"+ks+"x0", "_fQ2"+ks+"_x_0")
		t.copyToTop("q"+ks+"x1", "_fQ2"+ks+"_x_1")
		t.copyToTop("q"+ks+"y0", "_fQ2"+ks+"_y_0")
		t.copyToTop("q"+ks+"y1", "_fQ2"+ks+"_y_1")
		bn254G2FrobeniusP2(t, "_fQ2"+ks, "_Q2pre_"+ks)
		bn254G2Negate(t, "_Q2pre_"+ks, "_Q2_"+ks)

		// Correction lines use standard sparse evaluation
		bn254LineEvalAddSparse(t, tpfx, "_Q1_"+ks, ppfx+"x", ppfx+"y",
			tpfx+"c1", "_lq1_"+ks, "c1_"+ks)
		bn254RenameG2(t, tpfx+"c1", tpfx)
		bn254Fp12MulSparse(t, "_f", "_lq1_"+ks, "_f_c1_"+ks)
		bn254Fp12RenamePrefix(t, "_f_c1_"+ks, "_f")

		bn254LineEvalAddSparse(t, tpfx, "_Q2_"+ks, ppfx+"x", ppfx+"y",
			tpfx+"c2", "_lq2_"+ks, "c2_"+ks)
		bn254RenameG2(t, tpfx+"c2", tpfx)
		bn254Fp12MulSparse(t, "_f", "_lq2_"+ks, "_f_c2_"+ks)
		bn254Fp12RenamePrefix(t, "_f_c2_"+ks, "_f")
	}

	// Drop final T_k
	for k := 1; k <= 3; k++ {
		ks := string(rune('0' + k))
		bn254DropNames(t, []string{"_T" + ks + "_x_0", "_T" + ks + "_x_1",
			"_T" + ks + "_y_0", "_T" + ks + "_y_1"})
	}
}

// =========================================================================
// Witness-assisted final exponentiation
// =========================================================================

// emitWAFinalExp performs witness-assisted final exponentiation.
// The prover supplies f_inv, a=f2^x, b=f2^(x^2), c=f2^(x^3) as witness values,
// eliminating the 3 expensive ExpByX computations (~63 Fp12 squarings + ~30 Fp12
// multiplications each) and the Fp12 inverse in the easy part.
//
// Easy part:
//
//	f_conj = conj(f)              (cheap: negate the b-part)
//	verify f * f_inv == 1         (1 Fp12 mul + comparison)
//	f1 = f_conj * f_inv           (= f^(p^6 - 1))
//	f2 = f1 * frob_p2(f1)         (= f1^(p^2 + 1))
//
// Hard part (direct per-p-power assembly of the Fuentes-Castañeda /
// Duquesne-Ghammam exponent — gnark-crypto's BN254 FinalExponentiation):
//
//	e(x, p) = (1 + 6x + 12x² + 12x³)
//	        + (    4x + 6x² + 12x³) * p
//	        + (    6x + 6x² + 12x³) * p²
//	        + (-1 + 4x + 6x² + 12x³) * p³
//
// With witnesses a = f2^x, b = f2^x², c = f2^x³:
//
//	P0 = f2     · a^6 · b^12 · c^12
//	P1 =          a^4 · b^6  · c^12
//	P2 =          a^6 · b^6  · c^12
//	P3 = conj(f2)· a^4 · b^6  · c^12
//	result = P0 · Frob(P1) · FrobSq(P2) · FrobCube(P3)
//
// The a, b, c values are NOT individually verified. Any incorrect witness
// produces a wrong final result that fails the subsequent comparison
// against the precomputed e(alpha, beta) · pairing product == 1 check.
//
// This formula is pure-Go validated against gnark.FinalExponentiation by
// TestFinalExpWitnessesProduceCorrectResult in
// packages/runar-go/bn254witness/witness_test.go.
//
// Expected witness values on tracker (from unlocking script):
//
//	"_wa_finv" (12 Fp) — f^(-1)
//	"_wa_a"    (12 Fp) — f2^x
//	"_wa_b"    (12 Fp) — f2^(x^2)
//	"_wa_c"    (12 Fp) — f2^(x^3)
func emitWAFinalExp(t *BN254Tracker, fPrefix, resultPrefix string) {
	// === Easy part (witness-assisted) ===

	// Copy f before the inverse verify consumes it — we need conj(f) later.
	bn254Fp12CopyPrefix(t, fPrefix, "_wafe_fcopy")

	// Verify: f * f_inv == 1 in Fp12.
	// This drops fPrefix and renames "_wa_finv" to "_wafe_finv_v".
	emitWitnessInverseVerifyFp12(t, fPrefix, "_wa_finv", "_wafe_finv_v")

	// f_conj = conj(f) — conjugation negates the b-part of the Fp12 element.
	bn254Fp12Conjugate(t, "_wafe_fcopy", "_wafe_fconj")

	// f1 = f_conj * f_inv = f^(p^6 - 1)
	bn254Fp12Mul(t, "_wafe_fconj", "_wafe_finv_v", "_wafe_f1")

	// f2 = f1 * frob_p2(f1) = f1^(p^2 + 1)
	bn254Fp12CopyPrefix(t, "_wafe_f1", "_wafe_f1_frob")
	bn254Fp12FrobeniusP2(t, "_wafe_f1_frob", "_wafe_f1p2")
	bn254Fp12Mul(t, "_wafe_f1", "_wafe_f1p2", "_wafe_f2")

	// === Hard part (witness-assisted) ===
	// Plan: compute a^4, a^6, b^6, b^12, c^12 with exactly the copies that
	// the four P_i products need, then build P0..P3 and frobenius them,
	// then multiply them together into the final result.

	// ---- Prepare a^4 and a^6 (need 2 copies of each) ----
	// _wa_a remains intact; we work on a copy.
	bn254Fp12CopyPrefix(t, "_wa_a", "_wafe_a_w1")
	bn254Fp12Sqr(t, "_wafe_a_w1", "_wafe_a2") // a² (consumes _wafe_a_w1)
	// Need a² twice: once for (a²)²=a⁴, once for a⁴·a²=a⁶. So copy once and
	// consume the original in the first square below.
	bn254Fp12CopyPrefix(t, "_wafe_a2", "_wafe_a2_for_a6")
	bn254Fp12Sqr(t, "_wafe_a2", "_wafe_a4_core") // a⁴ (consumes _wafe_a2)
	// Need a⁴ three times total: once to feed into a⁶, once for P1, once for P3.
	// Make two copies; the remaining "_wafe_a4_core" is consumed by the a⁶ mul.
	bn254Fp12CopyPrefix(t, "_wafe_a4_core", "_wafe_a4_p1")
	bn254Fp12CopyPrefix(t, "_wafe_a4_core", "_wafe_a4_p3")
	bn254Fp12Mul(t, "_wafe_a4_core", "_wafe_a2_for_a6", "_wafe_a6_core")
	// Need a⁶ twice (P0 and P2). One copy + keep the core.
	bn254Fp12CopyPrefix(t, "_wafe_a6_core", "_wafe_a6_p2")
	bn254Fp12RenamePrefix(t, "_wafe_a6_core", "_wafe_a6_p0")

	// ---- Prepare b^6 and b^12 ----
	bn254Fp12CopyPrefix(t, "_wa_b", "_wafe_b_w1")
	bn254Fp12Sqr(t, "_wafe_b_w1", "_wafe_b2")
	bn254Fp12CopyPrefix(t, "_wafe_b2", "_wafe_b2_for_b6")
	bn254Fp12Sqr(t, "_wafe_b2", "_wafe_b4")
	bn254Fp12Mul(t, "_wafe_b4", "_wafe_b2_for_b6", "_wafe_b6_core")
	// Need b⁶ three times (P1, P2, P3) AND once to square into b¹². So 4 total.
	// Make 3 copies (p1, p2, p3); keep the core to feed the sqr for b¹².
	bn254Fp12CopyPrefix(t, "_wafe_b6_core", "_wafe_b6_p1")
	bn254Fp12CopyPrefix(t, "_wafe_b6_core", "_wafe_b6_p2")
	bn254Fp12CopyPrefix(t, "_wafe_b6_core", "_wafe_b6_p3")
	bn254Fp12Sqr(t, "_wafe_b6_core", "_wafe_b12_p0") // consumes _wafe_b6_core

	// ---- Prepare c^12 (need 4 copies) ----
	bn254Fp12CopyPrefix(t, "_wa_c", "_wafe_c_w1")
	bn254Fp12Sqr(t, "_wafe_c_w1", "_wafe_c2")
	bn254Fp12CopyPrefix(t, "_wafe_c2", "_wafe_c2_for_c6")
	bn254Fp12Sqr(t, "_wafe_c2", "_wafe_c4")
	bn254Fp12Mul(t, "_wafe_c4", "_wafe_c2_for_c6", "_wafe_c6")
	bn254Fp12Sqr(t, "_wafe_c6", "_wafe_c12_core") // c¹²
	bn254Fp12CopyPrefix(t, "_wafe_c12_core", "_wafe_c12_p0")
	bn254Fp12CopyPrefix(t, "_wafe_c12_core", "_wafe_c12_p1")
	bn254Fp12CopyPrefix(t, "_wafe_c12_core", "_wafe_c12_p2")
	bn254Fp12RenamePrefix(t, "_wafe_c12_core", "_wafe_c12_p3")

	// ---- Prepare f2 and conj(f2) ----
	// f2 is used in P0 (directly) and P3 (as conj(f2)). Copy once, rename once.
	bn254Fp12CopyPrefix(t, "_wafe_f2", "_wafe_f2_for_P3_src")
	bn254Fp12RenamePrefix(t, "_wafe_f2", "_wafe_f2_for_P0")

	// ---- Assemble P0 = f2 · a^6 · b^12 · c^12 ----
	bn254Fp12Mul(t, "_wafe_f2_for_P0", "_wafe_a6_p0", "_wafe_P0_s1")
	bn254Fp12Mul(t, "_wafe_P0_s1", "_wafe_b12_p0", "_wafe_P0_s2")
	bn254Fp12Mul(t, "_wafe_P0_s2", "_wafe_c12_p0", "_wafe_P0")

	// ---- Assemble P1 = a^4 · b^6 · c^12 ----
	bn254Fp12Mul(t, "_wafe_a4_p1", "_wafe_b6_p1", "_wafe_P1_s1")
	bn254Fp12Mul(t, "_wafe_P1_s1", "_wafe_c12_p1", "_wafe_P1")

	// ---- Assemble P2 = a^6 · b^6 · c^12 ----
	bn254Fp12Mul(t, "_wafe_a6_p2", "_wafe_b6_p2", "_wafe_P2_s1")
	bn254Fp12Mul(t, "_wafe_P2_s1", "_wafe_c12_p2", "_wafe_P2")

	// ---- Assemble P3 = conj(f2) · a^4 · b^6 · c^12 ----
	bn254Fp12Conjugate(t, "_wafe_f2_for_P3_src", "_wafe_f2conj")
	bn254Fp12Mul(t, "_wafe_f2conj", "_wafe_a4_p3", "_wafe_P3_s1")
	bn254Fp12Mul(t, "_wafe_P3_s1", "_wafe_b6_p3", "_wafe_P3_s2")
	bn254Fp12Mul(t, "_wafe_P3_s2", "_wafe_c12_p3", "_wafe_P3")

	// ---- Apply Frobenius powers ----
	// P1f = Frobenius(P1)
	bn254Fp12FrobeniusP(t, "_wafe_P1", "_wafe_P1f")
	// P2f = FrobeniusSquare(P2)
	bn254Fp12FrobeniusP2(t, "_wafe_P2", "_wafe_P2f")
	// P3f = FrobeniusCube(P3) = FrobeniusP(FrobeniusSquare(P3))
	bn254Fp12FrobeniusP2(t, "_wafe_P3", "_wafe_P3f_tmp")
	bn254Fp12FrobeniusP(t, "_wafe_P3f_tmp", "_wafe_P3f")

	// ---- Final product: result = P0 · P1f · P2f · P3f ----
	bn254Fp12Mul(t, "_wafe_P0", "_wafe_P1f", "_wafe_r1")
	bn254Fp12Mul(t, "_wafe_r1", "_wafe_P2f", "_wafe_r2")
	bn254Fp12Mul(t, "_wafe_r2", "_wafe_P3f", "_wafe_result")

	// Witnesses (_wa_a, _wa_b, _wa_c) are still on the stack — we only copied
	// them. Drop them now. _wafe_f2 was renamed away and is fully consumed,
	// so no separate drop is needed.
	bn254Fp12DropInputs(t, "_wa_a")
	bn254Fp12DropInputs(t, "_wa_b")
	bn254Fp12DropInputs(t, "_wa_c")

	// Rename result
	bn254Fp12RenamePrefix(t, "_wafe_result", resultPrefix)
}

// =========================================================================
// Main entry point
// =========================================================================

// EmitGroth16VerifierWitnessAssisted generates a complete Groth16 verification
// locking script using witness-assisted techniques.
//
// Verification equation (SP1 convention — negate β, γ, δ on the G2 side):
//
//	e(A, B) · e(L, -γ) · e(C, -δ) · e(α, -β) = 1
//
// where β, γ, δ are stored pre-negated in the config, and α, A, B, L,
// C are used positive.
//
// The generated script expects the following in the unlocking script (pushed by prover):
//   - All line gradients for Miller loop iterations (2 Fp values each, in Fp2)
//   - Final exponentiation witnesses: f_inv (12 Fp), a (12 Fp), b (12 Fp), c (12 Fp)
//   - prepared_inputs (G1, 2 Fp) — computed off-chain as
//     IC[0] + sum(pub_j * IC[j+1])
//   - The proof: A (2 Fp), B (4 Fp), C (2 Fp)
//
// The locking script:
//  1. Places q at stack bottom for efficient access
//  2. Verifies q matches the hardcoded BN254 field prime
//  3. On-curve checks the prover-supplied prepared_inputs G1 point
//  4. Runs triple Miller loop with witness-supplied gradients over
//     (A, B), (L, -γ), (C, -δ)
//  5. Multiplies by precomputed MillerLoop(α, -β)
//  6. Witness-assisted final exponentiation (prover supplies f_inv, a, b, c)
//  7. Checks result == 1 in Fp12
//
// NOTE: Public inputs are NOT on the stack. The prover runs the MSM
// off-chain (where 0 * IC = identity is handled natively) and supplies
// the accumulated G1 point directly. The on-chain verifier does not
// bind to specific public input values — the pairing check already
// discriminates between valid and invalid prepared_inputs values. This
// matches SP1's Solidity verifier, which computes the MSM via the BN254
// EC precompile and passes the result to the pairing precompile.
func EmitGroth16VerifierWitnessAssisted(emit func(StackOp), config Groth16Config) {
	// Count Miller loop iterations for gradient allocation
	naf := bn254SixXPlus2NAF
	msbIdx := len(naf) - 1
	for msbIdx > 0 && naf[msbIdx] == 0 {
		msbIdx--
	}

	// Build the initial stack names: these are the items the unlock script
	// has pushed (read bottom to top, i.e., first pushed = deepest).
	// The unlock script pushes q first, then gradients, then final exp witnesses,
	// then proof points, then public inputs.
	var initNames []string

	// q at bottom
	initNames = append(initNames, "_q")

	// For each Miller loop iteration, 3 doubling gradients (each 2 Fp values)
	// plus potential addition gradients.
	iterNum := 0
	for i := msbIdx - 1; i >= 0; i-- {
		for k := 1; k <= 3; k++ {
			ks := string(rune('0' + k))
			initNames = append(initNames,
				"_wlam_d"+ks+"_"+itoa(iterNum)+"_0",
				"_wlam_d"+ks+"_"+itoa(iterNum)+"_1",
			)
		}
		if naf[i] != 0 {
			for k := 1; k <= 3; k++ {
				ks := string(rune('0' + k))
				initNames = append(initNames,
					"_wlam_a"+ks+"_"+itoa(iterNum)+"_0",
					"_wlam_a"+ks+"_"+itoa(iterNum)+"_1",
				)
			}
		}
		iterNum++
	}

	// Final exponentiation witness values: f_inv (12 Fp), a (12 Fp), b (12 Fp), c (12 Fp)
	// These are the intermediate values the prover computes off-chain and supplies
	// so the script can skip the 3 expensive ExpByX calls and 1 Fp12 inverse.
	for _, waPrefix := range []string{"_wa_finv", "_wa_a", "_wa_b", "_wa_c"} {
		for _, part := range []string{"_a", "_b"} {
			for i := 0; i < 3; i++ {
				sfx := string(rune('0' + i))
				initNames = append(initNames, waPrefix+part+"_"+sfx+"_0")
				initNames = append(initNames, waPrefix+part+"_"+sfx+"_1")
			}
		}
	}

	// prepared_inputs (G1, prover-supplied): 2 Fp.
	// The prover computes IC[0] + sum(pub_j * IC[j+1]) off-chain using any
	// BN254 G1 implementation and pushes the result. On-chain the verifier
	// does a single on-curve check before using it as the P for pair 2.
	initNames = append(initNames, "_pi_x", "_pi_y")

	// G2 subgroup-check gradients for proof.B. The prover supplies one
	// Fp² gradient per doubling and one per addition in the witness-
	// assisted [6·x²]·B scalar-mul — see emitWAG2SubgroupCheck. Pushed
	// AFTER prepared_inputs and BEFORE the proof points so the tracker's
	// initial stack layout reads bottom-to-top as:
	//
	//   q, Miller gradients, final-exp witnesses, prepared_inputs,
	//   proof.B subgroup gradients (doublings then additions),
	//   proof_ax, proof_ay, proof_bx0 .. proof_by1, proof_cx, proof_cy
	initNames = appendSubgroupGradientNames(initNames)

	// Proof points: A (G1: 2 Fp), B (G2: 4 Fp), C (G1: 2 Fp)
	initNames = append(initNames, "proof_ax", "proof_ay")
	initNames = append(initNames, "proof_bx0", "proof_bx1", "proof_by0", "proof_by1")
	initNames = append(initNames, "proof_cx", "proof_cy")

	t := NewBN254Tracker(initNames, emit)

	// Step 1: Verify q is the correct BN254 field prime
	t.copyToTop("_q", "_q_check")
	t.pushBigInt("_q_expected", bn254FieldP)
	t.rawBlock([]string{"_q_check", "_q_expected"}, "", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_EQUALVERIFY"})
	})

	// Set q-at-bottom mode for efficient prime access
	t.SetQAtBottom()
	t.primeCacheActive = true
	t.modThreshold = config.ModuloThreshold

	// Step 2: Verify prepared_inputs (provided by prover as a witness).
	//
	// The prover computes prepared_inputs = IC[0] + sum(pub_j * IC[j+1])
	// off-chain using any BN254 implementation (e.g., gnark-crypto). The
	// on-chain verifier only needs to confirm the point is on the BN254 G1
	// curve. A dishonest prover who supplies a wrong prepared_inputs value
	// will fail the pairing check, so no explicit binding to the public
	// inputs is needed on-chain.
	//
	// This design matches SP1's Solidity verifier, which does the MSM via
	// the BN254 EC precompile off the verification logic path, and fixes
	// the zero-input bug of the previous on-chain MSM (0 * IC = identity,
	// which the strict Fp add helper cannot represent).
	emitWAG1OnCurveCheck(t, "_pi_x", "_pi_y")

	// Step 2a: Curve-membership checks on the prover-supplied proof points.
	//
	//   - proof.A (G1): y² == x³ + 3 mod p
	//   - proof.C (G1): y² == x³ + 3 mod p
	//   - proof.B (G2): y² == x³ + 3/(9+u) in Fp2 (on the BN254 twist curve)
	//   - proof.B (G2) subgroup check: see emitWAG2SubgroupCheck
	//     (partial — see TODO(subgroup-check) there).
	//
	// Without these checks the witness-assisted gradient equations
	// (lambda·(x₂-x₁) == y₂-y₁) are satisfiable by arbitrary coordinate
	// pairs that do NOT lie on the curve. A hostile prover could in
	// principle choose such an off-curve point and forge the pairing
	// identity — see Barreto et al., "Subgroup security in pairing-based
	// cryptography". The three on-curve checks plus the partial subgroup
	// defense close the broad class of these attacks; the narrow residual
	// (on-curve but in a small-order G2 subgroup) is documented in the
	// emitWAG2SubgroupCheck doc comment.
	emitWAG1OnCurveCheck(t, "proof_ax", "proof_ay")
	emitWAG1OnCurveCheck(t, "proof_cx", "proof_cy")
	emitWAG2OnCurveCheck(t, "proof_bx0", "proof_bx1", "proof_by0", "proof_by1")
	emitWAG2SubgroupCheck(t, "proof_bx0", "proof_bx1", "proof_by0", "proof_by1")

	// Step 3: Set up the 3 pairing pairs
	// Pair 1: (proof_A, proof_B)          — both positive
	// Pair 2: (prepared_inputs, -gamma)   — gamma pre-negated in VK
	// Pair 3: (proof_C, -delta)           — delta pre-negated in VK
	//
	// Groth16 verification equation (SP1 convention — negate β, γ, δ on
	// the G2 side, use A, B, L, C, α positive):
	//
	//   e(A, B) · e(L, -γ) · e(C, -δ) · e(α, -β) = 1
	//
	// where β, γ, δ are stored pre-negated in the config, and α, A, B,
	// L, C are used positive. The triple Miller loop handles the first
	// three pairs on-chain; e(α, -β) is baked into config.AlphaNegBetaFp12
	// as a precomputed MillerLoop constant that the verifier multiplies
	// into the accumulator before the single final exponentiation.

	// P1 = proof_A (positive)
	t.toTop("proof_ax")
	t.rename("p1x")
	t.toTop("proof_ay")
	t.rename("p1y")

	// Q1 = proof_B (positive, from unlock)
	t.toTop("proof_bx0")
	t.rename("q1x0")
	t.toTop("proof_bx1")
	t.rename("q1x1")
	t.toTop("proof_by0")
	t.rename("q1y0")
	t.toTop("proof_by1")
	t.rename("q1y1")

	// P2 = prepared_inputs (from step 2, positive)
	t.toTop("_pi_x")
	t.rename("p2x")
	t.toTop("_pi_y")
	t.rename("p2y")

	// Q2 = -gamma_G2 (hardcoded, pre-negated in VK)
	t.pushBigInt("q2x0", config.GammaNegG2[0])
	t.pushBigInt("q2x1", config.GammaNegG2[1])
	t.pushBigInt("q2y0", config.GammaNegG2[2])
	t.pushBigInt("q2y1", config.GammaNegG2[3])

	// P3 = proof_C (positive)
	t.toTop("proof_cx")
	t.rename("p3x")
	t.toTop("proof_cy")
	t.rename("p3y")

	// Q3 = -delta_G2 (hardcoded, pre-negated in VK)
	t.pushBigInt("q3x0", config.DeltaNegG2[0])
	t.pushBigInt("q3x1", config.DeltaNegG2[1])
	t.pushBigInt("q3y0", config.DeltaNegG2[2])
	t.pushBigInt("q3y1", config.DeltaNegG2[3])

	// Step 4: Triple Miller loop with witness-assisted gradients
	emitWAMillerLoop3(t)

	// Step 5: Multiply by precomputed MillerLoop(α, -β)
	// Push the 12 hardcoded Fp values
	for i := 0; i < 12; i++ {
		part := "_a"
		if i >= 6 {
			part = "_b"
		}
		idx := i % 6
		comp := idx / 2
		sub := idx % 2
		name := "_ab" + part + "_" + string(rune('0'+comp)) + "_" + string(rune('0'+sub))
		t.pushBigInt(name, config.AlphaNegBetaFp12[i])
	}

	bn254Fp12Mul(t, "_f", "_ab", "_f_with_ab")
	bn254Fp12RenamePrefix(t, "_f_with_ab", "_f")

	// Step 6: Witness-assisted final exponentiation
	// f_inv, a, b, c are already on the tracker from the unlocking script init.
	emitWAFinalExp(t, "_f", "_result")

	// Step 7: Check result == 1 in Fp12
	bn254Fp12IsOne(t, "_result", "_final_check")
	t.toTop("_final_check")
	t.rawBlock([]string{"_final_check"}, "", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_VERIFY"})
	})

	// Clean up P and Q inputs
	bn254DropNames(t, []string{"p1x", "p1y", "q1x0", "q1x1", "q1y0", "q1y1"})
	bn254DropNames(t, []string{"p2x", "p2y", "q2x0", "q2x1", "q2y0", "q2y1"})
	bn254DropNames(t, []string{"p3x", "p3y", "q3x0", "q3x1", "q3y0", "q3y1"})

	// Mark q-at-bottom mode ended so subsequent ops (if any) don't reach for
	// the alt/bottom prime. The actual _qbot_p on the main stack is dropped
	// by the sweeping cleanup below along with any other leftover items.
	t.qAtBottom = false
	t.primeCacheActive = false

	// Strict BSV consensus ("clean stack" rule) requires exactly ONE truthy
	// item on the main stack at script end. The Go-SDK interpreter is
	// lenient here (it accepts a non-empty stack with a truthy top), but
	// real BSV nodes reject non-clean stacks with "Script did not clean
	// its stack". Drop every remaining name the tracker knows about and
	// push a single OP_1 as the final success marker.
	for len(t.nm) > 0 {
		t.drop()
	}
	t.e(StackOp{Op: "push", Value: bigIntPush(1)})
	t.nm = append(t.nm, "_ok")
}

// =========================================================================
// MSM-binding variant — binds public inputs on-chain
// =========================================================================

// EmitGroth16VerifierWitnessAssistedWithMSM generates a witness-assisted
// Groth16 verification locking script that ADDITIONALLY binds the prover-
// supplied prepared_inputs to 5 explicit SP1 public-input scalars by
// computing IC[0] + Σ pub_i · IC[i+1] on-chain and asserting equality with
// the witness-supplied point.
//
// This is the soundness-strict counterpart to
// EmitGroth16VerifierWitnessAssisted. The raw variant accepts any on-curve
// prepared_inputs (the pairing check alone discriminates valid proofs),
// which is sound for trusted provers but allows a hostile prover to supply
// arbitrary prepared_inputs coordinates. The MSM variant closes that by
// recomputing the accumulator on-chain from public inputs pinned at
// compile time (via config.IC) and at call time (via the 5 pub_i scalars
// the unlocking script pushes).
//
// Witness stack layout (bottom → top, the prover's unlocking script order):
//
//	[q, Miller_gradients..., FinalExp_witnesses...,
//	 pub_0, pub_1, pub_2, pub_3, pub_4,
//	 prepared_inputs_x, prepared_inputs_y,
//	 proof_ax, proof_ay, proof_bx0, proof_bx1, proof_by0, proof_by1,
//	 proof_cx, proof_cy]
//
// The 5 pub_i scalars are consumed during the MSM computation and also
// kept alive as tracker names (_pub_0 .. _pub_4) for the duration of the
// preamble, so the method body can reference them via the
// Groth16PublicInput(i) DSL intrinsic.
//
// LIMIT: the 5-scalar MSM binding is intentional — it matches the SP1
// Groth16 verifier's fixed public-input arity (pub_0..pub_4). The scalars
// are consumed during MSM construction and then restored from the altstack
// at the end of the preamble so the method body can reference them via the
// Groth16PublicInput(i) DSL intrinsic (see the _pub_* altstack dance at
// the end of this function). Callers that rely on this arity:
//   - compilers/go/codegen/stack.go: emitGroth16WAPreamble (useMSM=true)
//   - packages/runar-go/bn254witness/witness.go (witness-stack layout)
//   - packages/runar-go/bn254.go (Groth16Config.IC documentation)
// Generalising to an arbitrary number of public inputs would require
// threading the arity through Groth16Config, the witness-stack layout,
// and the SP1Verifier contract DSL; that is out of scope for this
// function.
func EmitGroth16VerifierWitnessAssistedWithMSM(emit func(StackOp), config Groth16Config) {
	// Count Miller loop iterations for gradient allocation (same NAF
	// structure as the raw variant).
	naf := bn254SixXPlus2NAF
	msbIdx := len(naf) - 1
	for msbIdx > 0 && naf[msbIdx] == 0 {
		msbIdx--
	}

	var initNames []string
	initNames = append(initNames, "_q")

	iterNum := 0
	for i := msbIdx - 1; i >= 0; i-- {
		for k := 1; k <= 3; k++ {
			ks := string(rune('0' + k))
			initNames = append(initNames,
				"_wlam_d"+ks+"_"+itoa(iterNum)+"_0",
				"_wlam_d"+ks+"_"+itoa(iterNum)+"_1",
			)
		}
		if naf[i] != 0 {
			for k := 1; k <= 3; k++ {
				ks := string(rune('0' + k))
				initNames = append(initNames,
					"_wlam_a"+ks+"_"+itoa(iterNum)+"_0",
					"_wlam_a"+ks+"_"+itoa(iterNum)+"_1",
				)
			}
		}
		iterNum++
	}

	for _, waPrefix := range []string{"_wa_finv", "_wa_a", "_wa_b", "_wa_c"} {
		for _, part := range []string{"_a", "_b"} {
			for i := 0; i < 3; i++ {
				sfx := string(rune('0' + i))
				initNames = append(initNames, waPrefix+part+"_"+sfx+"_0")
				initNames = append(initNames, waPrefix+part+"_"+sfx+"_1")
			}
		}
	}

	// 5 SP1 public-input scalars — between the final-exp witnesses and
	// prepared_inputs.
	for i := 0; i < 5; i++ {
		initNames = append(initNames, "_pub_"+string(rune('0'+i)))
	}

	// prepared_inputs (G1, prover-supplied): 2 Fp. The MSM variant binds
	// this on-chain below rather than trusting the prover.
	initNames = append(initNames, "_pi_x", "_pi_y")

	// G2 subgroup-check gradients for proof.B — see the raw-variant
	// comment above for the layout.
	initNames = appendSubgroupGradientNames(initNames)

	// Proof points: A (G1: 2 Fp), B (G2: 4 Fp), C (G1: 2 Fp)
	initNames = append(initNames, "proof_ax", "proof_ay")
	initNames = append(initNames, "proof_bx0", "proof_bx1", "proof_by0", "proof_by1")
	initNames = append(initNames, "proof_cx", "proof_cy")

	t := NewBN254Tracker(initNames, emit)

	// Step 1: Verify q is the correct BN254 field prime.
	t.copyToTop("_q", "_q_check")
	t.pushBigInt("_q_expected", bn254FieldP)
	t.rawBlock([]string{"_q_check", "_q_expected"}, "", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_EQUALVERIFY"})
	})

	// Set q-at-bottom mode for efficient prime access.
	t.SetQAtBottom()
	t.primeCacheActive = true
	t.modThreshold = config.ModuloThreshold

	// Step 2: On-curve check on the prover-supplied prepared_inputs.
	emitWAG1OnCurveCheck(t, "_pi_x", "_pi_y")

	// Step 2a: Curve-membership checks on the prover-supplied proof points
	// (same soundness argument as the raw variant).
	emitWAG1OnCurveCheck(t, "proof_ax", "proof_ay")
	emitWAG1OnCurveCheck(t, "proof_cx", "proof_cy")
	emitWAG2OnCurveCheck(t, "proof_bx0", "proof_bx1", "proof_by0", "proof_by1")
	emitWAG2SubgroupCheck(t, "proof_bx0", "proof_bx1", "proof_by0", "proof_by1")

	// Step 2b: MSM binding — recompute
	//   msm = IC[0] + Σ_{i=0..4} pub_i · IC[i+1]
	// on-chain, then assert equality with the witness-supplied
	// prepared_inputs (_pi_x, _pi_y).
	//
	// This is the core soundness fix of the MSM variant: without it, the
	// prover could supply any on-curve G1 point as prepared_inputs and the
	// pairing would pass for a matching proof. Binding to config.IC pins
	// the public-inputs to VK-specific domain values.
	emitWAGroth16MSMBind(t, config)

	// Step 3: Set up the 3 pairing pairs (identical to the raw variant).
	t.toTop("proof_ax")
	t.rename("p1x")
	t.toTop("proof_ay")
	t.rename("p1y")

	t.toTop("proof_bx0")
	t.rename("q1x0")
	t.toTop("proof_bx1")
	t.rename("q1x1")
	t.toTop("proof_by0")
	t.rename("q1y0")
	t.toTop("proof_by1")
	t.rename("q1y1")

	t.toTop("_pi_x")
	t.rename("p2x")
	t.toTop("_pi_y")
	t.rename("p2y")

	t.pushBigInt("q2x0", config.GammaNegG2[0])
	t.pushBigInt("q2x1", config.GammaNegG2[1])
	t.pushBigInt("q2y0", config.GammaNegG2[2])
	t.pushBigInt("q2y1", config.GammaNegG2[3])

	t.toTop("proof_cx")
	t.rename("p3x")
	t.toTop("proof_cy")
	t.rename("p3y")

	t.pushBigInt("q3x0", config.DeltaNegG2[0])
	t.pushBigInt("q3x1", config.DeltaNegG2[1])
	t.pushBigInt("q3y0", config.DeltaNegG2[2])
	t.pushBigInt("q3y1", config.DeltaNegG2[3])

	// Step 4: Triple Miller loop.
	emitWAMillerLoop3(t)

	// Step 5: Multiply by precomputed MillerLoop(α, -β).
	for i := 0; i < 12; i++ {
		part := "_a"
		if i >= 6 {
			part = "_b"
		}
		idx := i % 6
		comp := idx / 2
		sub := idx % 2
		name := "_ab" + part + "_" + string(rune('0'+comp)) + "_" + string(rune('0'+sub))
		t.pushBigInt(name, config.AlphaNegBetaFp12[i])
	}

	bn254Fp12Mul(t, "_f", "_ab", "_f_with_ab")
	bn254Fp12RenamePrefix(t, "_f_with_ab", "_f")

	// Step 6: Witness-assisted final exponentiation.
	emitWAFinalExp(t, "_f", "_result")

	// Step 7: Check result == 1 in Fp12.
	bn254Fp12IsOne(t, "_result", "_final_check")
	t.toTop("_final_check")
	t.rawBlock([]string{"_final_check"}, "", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_VERIFY"})
	})

	// Clean up P and Q inputs.
	bn254DropNames(t, []string{"p1x", "p1y", "q1x0", "q1x1", "q1y0", "q1y1"})
	bn254DropNames(t, []string{"p2x", "p2y", "q2x0", "q2x1", "q2y0", "q2y1"})
	bn254DropNames(t, []string{"p3x", "p3y", "q3x0", "q3x1", "q3y0", "q3y1"})

	t.qAtBottom = false
	t.primeCacheActive = false

	// Preserve _pub_0 .. _pub_4 across the final cleanup so they remain on
	// the main stack, accessible to the method body via groth16PublicInput(i).
	// Move them to the altstack (in reverse order so they come back in the
	// correct ordering), drop everything else, restore.
	for i := 4; i >= 0; i-- {
		t.toTop("_pub_" + string(rune('0'+i)))
		t.toAlt()
	}
	// Drop every remaining intermediate on the main stack.
	for len(t.nm) > 0 {
		t.drop()
	}
	// Restore _pub_0 (first popped = alt top) through _pub_4. Final layout
	// on the main stack: [..., _pub_0, _pub_1, _pub_2, _pub_3, _pub_4].
	for i := 0; i < 5; i++ {
		t.fromAlt("_pub_" + string(rune('0'+i)))
	}

	// Push OP_1 as the final truthy marker (same as raw).
	t.e(StackOp{Op: "push", Value: bigIntPush(1)})
	t.nm = append(t.nm, "_ok")
}

// emitWAGroth16MSMBind recomputes the Groth16 prepared-inputs accumulator
// on-chain and asserts it matches the prover-supplied _pi_x, _pi_y.
//
// The accumulator is
//
//	msm = IC[0] + Σ_{i=0..4} pub_i · IC[i+1]
//
// Each scalar multiplication reuses the generic G1 scalar-mul path (cf.
// EmitBN254G1ScalarMul) and each addition reuses the affine add. Both are
// called via the existing BN254Tracker plumbing (decompose / compose /
// bn254G1AffineAdd / bn254G1JacobianDouble).
//
// Zero-scalar handling: when pub_i == 0, the term pub_i · IC[i+1] is the
// group identity O, which has no affine (x, y) representation. More
// practically, the Jacobian double-and-add trajectory for k' = 3r (the
// k=0 case) passes through the acc = -base state, which
// bn254BuildJacobianAddAffineInline deliberately does NOT handle (see the
// comment on that function), producing a wrong point rather than O. SP1
// Groth16 proofs routinely include public inputs equal to 0 (the fixture
// under tests/vectors/sp1/v6.0.0 has pub_2 = pub_4 = 0), so the zero case
// must be handled explicitly for the MSM-binding preamble to match
// computePreparedInputs off-chain.
//
// Implementation: each term is wrapped in OP_IF guarded by (pub_i != 0).
// In the non-zero branch we run the existing scalar-mul + affine-add and
// then use the altstack to clean up the intermediate garbage so both
// branches leave the same stack shape. In the zero branch we just drop
// the pushed IC[i+1] base point; acc_x / acc_y stay untouched.
//
// Semantics on failure: the final equality check against _pi_x / _pi_y
// uses OP_EQUALVERIFY on each coordinate, aborting the script when they
// disagree. The 5 pub_i scalars and _pi_x / _pi_y are consumed; the G1
// constants for IC points are also consumed (they are materialized via
// pushBigInt inside the scalar-mul loop).
func emitWAGroth16MSMBind(t *BN254Tracker, config Groth16Config) {
	pfx := "_msm_"

	// Start accumulator = IC[0] in affine form (px, py).
	t.pushBigInt(pfx+"acc_x", config.IC[0][0])
	t.pushBigInt(pfx+"acc_y", config.IC[0][1])

	accXName := pfx + "acc_x"
	accYName := pfx + "acc_y"

	for i := 0; i < 5; i++ {
		// Scalar: pub_i (bring from the witness slot on the main stack).
		scalarName := "_pub_" + string(rune('0'+i))

		// Push IC[i+1] as the base point (affine bx, by).
		bxName := pfx + "bx_" + itoa(i)
		byName := pfx + "by_" + itoa(i)
		t.pushBigInt(bxName, config.IC[i+1][0])
		t.pushBigInt(byName, config.IC[i+1][1])

		// Compute the OP_IF condition: flag = (pub_i != 0). OP_0NOTEQUAL
		// collapses any nonzero bigint to 1 and 0 to 0.
		chkName := pfx + "chk_" + itoa(i)
		isNzName := pfx + "is_nz_" + itoa(i)
		t.copyToTop(scalarName, chkName)
		t.rawBlock([]string{chkName}, isNzName, func(e func(StackOp)) {
			e(StackOp{Op: "opcode", Code: "OP_0NOTEQUAL"})
		})
		// Consume the flag for OP_IF.
		t.toTop(isNzName)
		t.nm = t.nm[:len(t.nm)-1]

		// Snapshot the tracker state entering the branches. Both inner
		// trackers start with a copy of this nm.
		branchInit := append([]string{}, t.nm...)
		branchLen := len(branchInit)

		// ------------------------------------------------------------------
		// Non-zero branch: compute tx/ty = pub_i · IC[i+1], then acc += term.
		// ------------------------------------------------------------------
		var nonzeroOps []StackOp
		nonzeroEmit := func(op StackOp) { nonzeroOps = append(nonzeroOps, op) }
		nz := NewBN254Tracker(append([]string{}, branchInit...), nonzeroEmit)
		nz.primeCacheActive = t.primeCacheActive
		nz.qAtBottom = t.qAtBottom
		nz.modThreshold = t.modThreshold

		txName := pfx + "tx_" + itoa(i)
		tyName := pfx + "ty_" + itoa(i)
		newAccX := pfx + "new_acc_x_" + itoa(i)
		newAccY := pfx + "new_acc_y_" + itoa(i)

		emitG1ScalarMulNamed(nz, bxName, byName, scalarName, txName, tyName)
		emitG1AffineAddNamed(nz, accXName, accYName, txName, tyName, newAccX, newAccY)

		// Rename the new acc coords to the stable names so both branches
		// expose the same top-of-stack names after the IF.
		nz.toTop(newAccX)
		nz.rename(accXName)
		nz.toTop(newAccY)
		nz.rename(accYName)

		// Stash the new acc on the altstack so we can drop all the
		// scalar-mul / affine-add intermediates without losing them.
		// Order: push acc_y first (ends up below on alt), then acc_x
		// (ends up on top of alt). Pops in forward (x then y) order.
		nz.toTop(accYName)
		nz.toAlt()
		nz.toTop(accXName)
		nz.toAlt()

		// Drop every intermediate left on the main stack. After this,
		// the main stack matches the pre-iteration state with the old
		// acc_x / acc_y / bx / by consumed (length branchLen - 4).
		dropTarget := branchLen - 4
		for len(nz.nm) > dropTarget {
			nz.drop()
		}

		// Restore the new acc coords from the altstack.
		nz.fromAlt(accXName)
		nz.fromAlt(accYName)

		// ------------------------------------------------------------------
		// Zero branch: acc unchanged; discard the pushed IC base point.
		// ------------------------------------------------------------------
		var zeroOps []StackOp
		zeroEmit := func(op StackOp) { zeroOps = append(zeroOps, op) }
		zr := NewBN254Tracker(append([]string{}, branchInit...), zeroEmit)
		zr.primeCacheActive = t.primeCacheActive
		zr.qAtBottom = t.qAtBottom
		zr.modThreshold = t.modThreshold

		zr.toTop(byName)
		zr.drop()
		zr.toTop(bxName)
		zr.drop()

		// Sanity-check: both branches must agree on the final nm so the
		// outer tracker stays coherent.
		if len(nz.nm) != len(zr.nm) {
			panic(fmt.Sprintf(
				"emitWAGroth16MSMBind: branch length mismatch at i=%d: nz=%d zr=%d",
				i, len(nz.nm), len(zr.nm),
			))
		}
		for j := range nz.nm {
			if nz.nm[j] != zr.nm[j] {
				panic(fmt.Sprintf(
					"emitWAGroth16MSMBind: branch nm mismatch at i=%d pos=%d: nz=%q zr=%q",
					i, j, nz.nm[j], zr.nm[j],
				))
			}
		}

		t.e(StackOp{Op: "if", Then: nonzeroOps, Else: zeroOps})
		t.nm = append([]string{}, nz.nm...)
	}

	// Assert (acc_x, acc_y) == (_pi_x, _pi_y).
	bn254FieldMod(t, pfx+"acc_x", pfx+"acc_x_r")
	bn254FieldMod(t, pfx+"acc_y", pfx+"acc_y_r")
	t.copyToTop("_pi_x", pfx+"pix")
	bn254FieldMod(t, pfx+"pix", pfx+"pix_r")
	t.copyToTop("_pi_y", pfx+"piy")
	bn254FieldMod(t, pfx+"piy", pfx+"piy_r")

	t.toTop(pfx + "acc_x_r")
	t.toTop(pfx + "pix_r")
	t.rawBlock([]string{pfx + "acc_x_r", pfx + "pix_r"}, "", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_EQUALVERIFY"})
	})
	t.toTop(pfx + "acc_y_r")
	t.toTop(pfx + "piy_r")
	t.rawBlock([]string{pfx + "acc_y_r", pfx + "piy_r"}, "", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_EQUALVERIFY"})
	})
}

// emitG1ScalarMulNamed computes resultX, resultY = scalar · (bx, by) in
// affine form, using a 254-bit double-and-add over Jacobian coordinates.
// The inputs bx, by are consumed (they go through bn254G1AffineAdd-style
// sub-patterns via copy+move); the scalar name is copied, not consumed.
//
// This mirrors EmitBN254G1ScalarMul but operates directly on named raw-Fp
// coordinates on the tracker instead of the 64-byte Point blob form.
func emitG1ScalarMulNamed(t *BN254Tracker, bxName, byName, scalarName, resultXName, resultYName string) {
	// Rename base (bx, by) to the names the Jacobian add/double helpers
	// expect: ax / ay (affine base point).
	t.toTop(bxName)
	t.rename("ax")
	t.toTop(byName)
	t.rename("ay")

	// k' = scalar + 3r: guarantees bit 255 is set. Same trick as
	// EmitBN254G1ScalarMul so bit 254 (index 254) is always 1 and we can
	// initialise the accumulator unconditionally from the base.
	t.copyToTop(scalarName, "_k")
	t.pushBigInt("_r1", bn254CurveR)
	t.rawBlock([]string{"_k", "_r1"}, "_kr1", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_ADD"})
	})
	t.pushBigInt("_r2", bn254CurveR)
	t.rawBlock([]string{"_kr1", "_r2"}, "_kr2", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_ADD"})
	})
	t.pushBigInt("_r3", bn254CurveR)
	t.rawBlock([]string{"_kr2", "_r3"}, "_kr3", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_ADD"})
	})
	t.rename("_k")

	// Init accumulator = P in Jacobian coords (bit 255 of k+3r is always 1).
	t.copyToTop("ax", "jx")
	t.copyToTop("ay", "jy")
	t.pushInt("jz", 1)

	// 255 iterations: bits 254 down to 0.
	for bit := 254; bit >= 0; bit-- {
		bn254G1JacobianDouble(t)

		t.copyToTop("_k", "_k_copy")
		if bit == 1 {
			t.rawBlock([]string{"_k_copy"}, "_shifted", func(e func(StackOp)) {
				e(StackOp{Op: "opcode", Code: "OP_2DIV"})
			})
		} else if bit > 1 {
			t.pushInt("_shift", int64(bit))
			t.rawBlock([]string{"_k_copy", "_shift"}, "_shifted", func(e func(StackOp)) {
				e(StackOp{Op: "opcode", Code: "OP_RSHIFTNUM"})
			})
		} else {
			t.rename("_shifted")
		}
		t.pushInt("_two", 2)
		t.rawBlock([]string{"_shifted", "_two"}, "_bit", func(e func(StackOp)) {
			e(StackOp{Op: "opcode", Code: "OP_MOD"})
		})

		t.toTop("_bit")
		t.nm = t.nm[:len(t.nm)-1] // _bit consumed by IF
		var addOps []StackOp
		addEmit := func(op StackOp) { addOps = append(addOps, op) }
		bn254BuildJacobianAddAffineInline(addEmit, t)
		t.e(StackOp{Op: "if", Then: addOps, Else: []StackOp{}})
	}

	// Jacobian -> affine.
	bn254G1JacobianToAffine(t, resultXName, resultYName)

	// Clean up base point and scalar.
	t.toTop("ax")
	t.drop()
	t.toTop("ay")
	t.drop()
	t.toTop("_k")
	t.drop()
}

// emitG1AffineAddNamed computes (rx, ry) = (p1x, p1y) + (p2x, p2y) in
// affine form on the BN254 curve, consuming all four input coordinates.
//
// Wraps bn254G1AffineAdd (which expects the names "px, py, qx, qy" and
// writes to "rx, ry") with rename plumbing so the caller can use arbitrary
// names for inputs and outputs.
func emitG1AffineAddNamed(t *BN254Tracker, p1x, p1y, p2x, p2y, resultX, resultY string) {
	t.toTop(p1x)
	t.rename("px")
	t.toTop(p1y)
	t.rename("py")
	t.toTop(p2x)
	t.rename("qx")
	t.toTop(p2y)
	t.rename("qy")
	bn254G1AffineAdd(t)
	t.toTop("rx")
	t.rename(resultX)
	t.toTop("ry")
	t.rename(resultY)
}

// =========================================================================
// Standalone emit functions for testing primitives
// =========================================================================

// EmitWitnessInverseVerifyFp emits a script that verifies a * a_inv mod p == 1.
// Stack in:  [a, a_inv]  (a_inv on top)
// Stack out: [a_inv]     (verified inverse)
// Script fails if the inverse is incorrect.
func EmitWitnessInverseVerifyFp(emit func(StackOp)) {
	t := NewBN254Tracker([]string{"a", "a_inv"}, emit)
	t.PushPrimeCache()
	emitWitnessInverseVerify(t, "a", "a_inv", "result")
	t.PopPrimeCache()
}

// EmitWitnessGradientVerifyFp emits a script that verifies lambda * denom == numer (mod p).
// Stack in:  [lambda, denom, numer]  (numer on top)
// Stack out: [lambda]                (verified gradient)
// Script fails if the gradient is incorrect.
func EmitWitnessGradientVerifyFp(emit func(StackOp)) {
	t := NewBN254Tracker([]string{"lambda", "denom", "numer"}, emit)
	t.PushPrimeCache()
	emitWitnessGradientVerifyFp(t, "lambda", "denom", "numer", "result")
	t.PopPrimeCache()
}

// EmitWAFinalExpA6Debug is a debugging wrapper that runs EXACTLY the
// a^6 preparation sequence of emitWAFinalExp (including the "fanout"
// copies for P1 and P3) and leaves _wafe_a6_p0 on top of stack in prefix
// order (a_0_0 deepest, b_2_1 on top). Used by the witness-package script
// tests to compare the codegen's a^6 computation against gnark's.
//
// Stack layout expected: just _wa_a (12 slots) in prefix order.
func EmitWAFinalExpA6Debug(emit func(StackOp)) {
	initNames := []string{}
	for _, part := range []string{"_a", "_b"} {
		for i := 0; i < 3; i++ {
			sfx := string(rune('0' + i))
			initNames = append(initNames, "_wa_a"+part+"_"+sfx+"_0")
			initNames = append(initNames, "_wa_a"+part+"_"+sfx+"_1")
		}
	}
	t := NewBN254Tracker(initNames, emit)
	t.PushPrimeCache()

	// Replicate the a^4/a^6 preparation of emitWAFinalExp verbatim.
	bn254Fp12CopyPrefix(t, "_wa_a", "_wafe_a_w1")
	bn254Fp12Sqr(t, "_wafe_a_w1", "_wafe_a2")
	bn254Fp12CopyPrefix(t, "_wafe_a2", "_wafe_a2_for_a6")
	bn254Fp12Sqr(t, "_wafe_a2", "_wafe_a4_core")
	bn254Fp12CopyPrefix(t, "_wafe_a4_core", "_wafe_a4_p1")
	bn254Fp12CopyPrefix(t, "_wafe_a4_core", "_wafe_a4_p3")
	bn254Fp12Mul(t, "_wafe_a4_core", "_wafe_a2_for_a6", "_wafe_a6_core")
	bn254Fp12CopyPrefix(t, "_wafe_a6_core", "_wafe_a6_p2")
	bn254Fp12RenamePrefix(t, "_wafe_a6_core", "_wafe_a6_p0")

	// Drop _wa_a (we only copied it), _wafe_a4_p1, _wafe_a4_p3, _wafe_a6_p2.
	bn254Fp12DropInputs(t, "_wa_a")
	bn254Fp12DropInputs(t, "_wafe_a4_p1")
	bn254Fp12DropInputs(t, "_wafe_a4_p3")
	bn254Fp12DropInputs(t, "_wafe_a6_p2")

	// Move _wafe_a6_p0 to the top in prefix order (a_0_0 deepest, b_2_1 top).
	for _, part := range []string{"_a", "_b"} {
		for i := 0; i < 3; i++ {
			sfx := string(rune('0' + i))
			t.toTop("_wafe_a6_p0" + part + "_" + sfx + "_0")
			t.toTop("_wafe_a6_p0" + part + "_" + sfx + "_1")
		}
	}

	t.PopPrimeCache()
}

// EmitG2FrobeniusPStandalone runs bn254G2FrobeniusP on a 4-Fp-slot G2 input
// (Qx_0, Qx_1, Qy_0, Qy_1, top-of-stack) and leaves 4 Fp slots of the result
// on top. Test harness for the G2 pi map used in Miller loop corrections.
func EmitG2FrobeniusPStandalone(emit func(StackOp)) {
	initNames := []string{"_Q_x_0", "_Q_x_1", "_Q_y_0", "_Q_y_1"}
	t := NewBN254Tracker(initNames, emit)
	t.PushPrimeCache()
	bn254G2FrobeniusP(t, "_Q", "_R")
	bn254FieldMod(t, "_R_x_0", "_R_x_0_r")
	bn254FieldMod(t, "_R_x_1", "_R_x_1_r")
	bn254FieldMod(t, "_R_y_0", "_R_y_0_r")
	bn254FieldMod(t, "_R_y_1", "_R_y_1_r")
	t.toTop("_R_x_0_r")
	t.toTop("_R_x_1_r")
	t.toTop("_R_y_0_r")
	t.toTop("_R_y_1_r")
	t.PopPrimeCache()
}

// EmitG2FrobeniusP2Standalone is the p²-Frobenius counterpart.
func EmitG2FrobeniusP2Standalone(emit func(StackOp)) {
	initNames := []string{"_Q_x_0", "_Q_x_1", "_Q_y_0", "_Q_y_1"}
	t := NewBN254Tracker(initNames, emit)
	t.PushPrimeCache()
	bn254G2FrobeniusP2(t, "_Q", "_R")
	bn254FieldMod(t, "_R_x_0", "_R_x_0_r")
	bn254FieldMod(t, "_R_x_1", "_R_x_1_r")
	bn254FieldMod(t, "_R_y_0", "_R_y_0_r")
	bn254FieldMod(t, "_R_y_1", "_R_y_1_r")
	t.toTop("_R_x_0_r")
	t.toTop("_R_x_1_r")
	t.toTop("_R_y_0_r")
	t.toTop("_R_y_1_r")
	t.PopPrimeCache()
}

// EmitFp12MulSparseStandalone is a test harness for bn254Fp12MulSparse.
// Stack layout: 12 Fp values for the dense element, then 6 Fp values for
// the sparse element. The sparse element is in the canonical gnark-crypto
// BN254 form with slots (c0, c3, c4) populating Fp12 positions (C0.B0, C1.B0,
// C1.B1). The sparse layout in slot order is:
//
//	sparse_c0_0, sparse_c0_1,
//	sparse_c3_0, sparse_c3_1,
//	sparse_c4_0, sparse_c4_1   (6 Fp values; c4_1 on top of stack)
//
// Stack out: 12 Fp for the product in prefix order.
func EmitFp12MulSparseStandalone(emit func(StackOp)) {
	initNames := []string{}
	// Dense: _d_a_0_0 ... _d_b_2_1
	for _, part := range []string{"_a", "_b"} {
		for i := 0; i < 3; i++ {
			sfx := string(rune('0' + i))
			initNames = append(initNames, "_d"+part+"_"+sfx+"_0")
			initNames = append(initNames, "_d"+part+"_"+sfx+"_1")
		}
	}
	// Sparse: _s_c0_0, _s_c0_1, _s_c3_0, _s_c3_1, _s_c4_0, _s_c4_1
	initNames = append(initNames,
		"_s_c0_0", "_s_c0_1",
		"_s_c3_0", "_s_c3_1",
		"_s_c4_0", "_s_c4_1",
	)
	t := NewBN254Tracker(initNames, emit)
	t.PushPrimeCache()
	bn254Fp12MulSparse(t, "_d", "_s", "_r")
	for _, part := range []string{"_a", "_b"} {
		for i := 0; i < 3; i++ {
			sfx := string(rune('0' + i))
			bn254FieldMod(t, "_r"+part+"_"+sfx+"_0", "_r"+part+"_"+sfx+"_0_r")
			bn254FieldMod(t, "_r"+part+"_"+sfx+"_1", "_r"+part+"_"+sfx+"_1_r")
		}
	}
	for _, part := range []string{"_a", "_b"} {
		for i := 0; i < 3; i++ {
			sfx := string(rune('0' + i))
			t.toTop("_r" + part + "_" + sfx + "_0_r")
			t.toTop("_r" + part + "_" + sfx + "_1_r")
		}
	}
	t.PopPrimeCache()
}

// EmitFp12FrobeniusPStandalone applies FrobeniusP (p-power Frobenius) to
// a 12-Fp-slot input and leaves the 12-slot result on top.
func EmitFp12FrobeniusPStandalone(emit func(StackOp)) {
	initNames := []string{}
	for _, part := range []string{"_a", "_b"} {
		for i := 0; i < 3; i++ {
			sfx := string(rune('0' + i))
			initNames = append(initNames, "_a"+part+"_"+sfx+"_0")
			initNames = append(initNames, "_a"+part+"_"+sfx+"_1")
		}
	}
	t := NewBN254Tracker(initNames, emit)
	t.PushPrimeCache()
	bn254Fp12FrobeniusP(t, "_a", "_r")
	for _, part := range []string{"_a", "_b"} {
		for i := 0; i < 3; i++ {
			sfx := string(rune('0' + i))
			bn254FieldMod(t, "_r"+part+"_"+sfx+"_0", "_r"+part+"_"+sfx+"_0_r")
			bn254FieldMod(t, "_r"+part+"_"+sfx+"_1", "_r"+part+"_"+sfx+"_1_r")
		}
	}
	for _, part := range []string{"_a", "_b"} {
		for i := 0; i < 3; i++ {
			sfx := string(rune('0' + i))
			t.toTop("_r" + part + "_" + sfx + "_0_r")
			t.toTop("_r" + part + "_" + sfx + "_1_r")
		}
	}
	t.PopPrimeCache()
}

// EmitFp12FrobeniusP2Standalone applies FrobeniusP2 to a 12-Fp-slot input
// and leaves the result on top of stack. Used as a primitive-correctness
// sanity test against gnark's E12.FrobeniusSquare.
func EmitFp12FrobeniusP2Standalone(emit func(StackOp)) {
	initNames := []string{}
	for _, part := range []string{"_a", "_b"} {
		for i := 0; i < 3; i++ {
			sfx := string(rune('0' + i))
			initNames = append(initNames, "_a"+part+"_"+sfx+"_0")
			initNames = append(initNames, "_a"+part+"_"+sfx+"_1")
		}
	}
	t := NewBN254Tracker(initNames, emit)
	t.PushPrimeCache()
	bn254Fp12FrobeniusP2(t, "_a", "_r")
	// Reduce each component for canonical comparison.
	for _, part := range []string{"_a", "_b"} {
		for i := 0; i < 3; i++ {
			sfx := string(rune('0' + i))
			bn254FieldMod(t, "_r"+part+"_"+sfx+"_0", "_r"+part+"_"+sfx+"_0_r")
			bn254FieldMod(t, "_r"+part+"_"+sfx+"_1", "_r"+part+"_"+sfx+"_1_r")
		}
	}
	for _, part := range []string{"_a", "_b"} {
		for i := 0; i < 3; i++ {
			sfx := string(rune('0' + i))
			t.toTop("_r" + part + "_" + sfx + "_0_r")
			t.toTop("_r" + part + "_" + sfx + "_1_r")
		}
	}
	t.PopPrimeCache()
}

// EmitFp12SqrStandalone emits a script that squares a 12-Fp-slot Fp12 value
// pushed on the stack (gnark flat order) and leaves the 12-slot result on
// top. Used to sanity-check bn254Fp12Sqr against gnark's Square.
//
// Stack layout expected (deepest → top): _a_a_0_0 ... _a_b_2_1 (12 slots).
// Stack out: 12 Fp slots of result.
func EmitFp12SqrStandalone(emit func(StackOp)) {
	initNames := []string{}
	for _, part := range []string{"_a", "_b"} {
		for i := 0; i < 3; i++ {
			sfx := string(rune('0' + i))
			initNames = append(initNames, "_a"+part+"_"+sfx+"_0")
			initNames = append(initNames, "_a"+part+"_"+sfx+"_1")
		}
	}
	t := NewBN254Tracker(initNames, emit)
	t.PushPrimeCache()
	bn254Fp12Sqr(t, "_a", "_r")
	// Move _r slots to the top in a predictable order for the caller to
	// inspect: deepest is _r_a_0_0, top is _r_b_2_1.
	for _, part := range []string{"_a", "_b"} {
		for i := 0; i < 3; i++ {
			sfx := string(rune('0' + i))
			t.toTop("_r" + part + "_" + sfx + "_0")
			t.toTop("_r" + part + "_" + sfx + "_1")
		}
	}
	t.PopPrimeCache()
}

// EmitFp12MulStandalone is the Fp12 multiplication counterpart of
// EmitFp12SqrStandalone. Stack layout: 12 slots for a, then 12 slots for b
// (b on top). Stack out: 12 slots for a*b.
func EmitFp12MulStandalone(emit func(StackOp)) {
	initNames := []string{}
	for _, pfx := range []string{"_a", "_b"} {
		for _, part := range []string{"_a", "_b"} {
			for i := 0; i < 3; i++ {
				sfx := string(rune('0' + i))
				initNames = append(initNames, pfx+part+"_"+sfx+"_0")
				initNames = append(initNames, pfx+part+"_"+sfx+"_1")
			}
		}
	}
	t := NewBN254Tracker(initNames, emit)
	t.PushPrimeCache()
	bn254Fp12Mul(t, "_a", "_b", "_r")
	for _, part := range []string{"_a", "_b"} {
		for i := 0; i < 3; i++ {
			sfx := string(rune('0' + i))
			t.toTop("_r" + part + "_" + sfx + "_0")
			t.toTop("_r" + part + "_" + sfx + "_1")
		}
	}
	t.PopPrimeCache()
}

// EmitWAFinalExpF2Debug runs only the easy part of emitWAFinalExp and
// leaves _wafe_f2 on top of stack. Used to verify that the easy-part
// computation matches gnark's (conj(f)·f^-1)·frob_p2(·).
func EmitWAFinalExpF2Debug(emit func(StackOp)) {
	initNames := []string{}
	for _, prefix := range []string{"_f", "_wa_finv", "_wa_a", "_wa_b", "_wa_c"} {
		for _, part := range []string{"_a", "_b"} {
			for i := 0; i < 3; i++ {
				sfx := string(rune('0' + i))
				initNames = append(initNames, prefix+part+"_"+sfx+"_0")
				initNames = append(initNames, prefix+part+"_"+sfx+"_1")
			}
		}
	}
	t := NewBN254Tracker(initNames, emit)
	t.PushPrimeCache()

	// Easy part only.
	bn254Fp12CopyPrefix(t, "_f", "_wafe_fcopy")
	emitWitnessInverseVerifyFp12(t, "_f", "_wa_finv", "_wafe_finv_v")
	bn254Fp12Conjugate(t, "_wafe_fcopy", "_wafe_fconj")
	bn254Fp12Mul(t, "_wafe_fconj", "_wafe_finv_v", "_wafe_f1")
	bn254Fp12CopyPrefix(t, "_wafe_f1", "_wafe_f1_frob")
	bn254Fp12FrobeniusP2(t, "_wafe_f1_frob", "_wafe_f1p2")
	bn254Fp12Mul(t, "_wafe_f1", "_wafe_f1p2", "_wafe_f2")

	// Drop the unused witnesses.
	bn254Fp12DropInputs(t, "_wa_a")
	bn254Fp12DropInputs(t, "_wa_b")
	bn254Fp12DropInputs(t, "_wa_c")

	// Reduce f2 and bring to top.
	for _, part := range []string{"_a", "_b"} {
		for i := 0; i < 3; i++ {
			sfx := string(rune('0' + i))
			bn254FieldMod(t, "_wafe_f2"+part+"_"+sfx+"_0", "_wafe_f2"+part+"_"+sfx+"_0_r")
			bn254FieldMod(t, "_wafe_f2"+part+"_"+sfx+"_1", "_wafe_f2"+part+"_"+sfx+"_1_r")
		}
	}
	for _, part := range []string{"_a", "_b"} {
		for i := 0; i < 3; i++ {
			sfx := string(rune('0' + i))
			t.toTop("_wafe_f2" + part + "_" + sfx + "_0_r")
			t.toTop("_wafe_f2" + part + "_" + sfx + "_1_r")
		}
	}
	t.PopPrimeCache()
}

// EmitWAFinalExpP0Debug runs only the easy part + P0 assembly of
// emitWAFinalExp and leaves the 12-slot _wafe_P0 on top. Used to check
// whether P0 = f2 · a^6 · b^12 · c^12 is computed correctly.
func EmitWAFinalExpP0Debug(emit func(StackOp)) {
	initNames := []string{}
	for _, prefix := range []string{"_f", "_wa_finv", "_wa_a", "_wa_b", "_wa_c"} {
		for _, part := range []string{"_a", "_b"} {
			for i := 0; i < 3; i++ {
				sfx := string(rune('0' + i))
				initNames = append(initNames, prefix+part+"_"+sfx+"_0")
				initNames = append(initNames, prefix+part+"_"+sfx+"_1")
			}
		}
	}
	t := NewBN254Tracker(initNames, emit)
	t.PushPrimeCache()

	// === Easy part (same as emitWAFinalExp) ===
	bn254Fp12CopyPrefix(t, "_f", "_wafe_fcopy")
	emitWitnessInverseVerifyFp12(t, "_f", "_wa_finv", "_wafe_finv_v")
	bn254Fp12Conjugate(t, "_wafe_fcopy", "_wafe_fconj")
	bn254Fp12Mul(t, "_wafe_fconj", "_wafe_finv_v", "_wafe_f1")
	bn254Fp12CopyPrefix(t, "_wafe_f1", "_wafe_f1_frob")
	bn254Fp12FrobeniusP2(t, "_wafe_f1_frob", "_wafe_f1p2")
	bn254Fp12Mul(t, "_wafe_f1", "_wafe_f1p2", "_wafe_f2")

	// === a^6, b^12, c^12, f2 preparation (single-copy variants: we only need P0) ===
	bn254Fp12CopyPrefix(t, "_wa_a", "_wafe_a_w1")
	bn254Fp12Sqr(t, "_wafe_a_w1", "_wafe_a2")
	bn254Fp12CopyPrefix(t, "_wafe_a2", "_wafe_a2_for_a6")
	bn254Fp12Sqr(t, "_wafe_a2", "_wafe_a4_core")
	bn254Fp12Mul(t, "_wafe_a4_core", "_wafe_a2_for_a6", "_wafe_a6_p0")

	bn254Fp12CopyPrefix(t, "_wa_b", "_wafe_b_w1")
	bn254Fp12Sqr(t, "_wafe_b_w1", "_wafe_b2")
	bn254Fp12CopyPrefix(t, "_wafe_b2", "_wafe_b2_for_b6")
	bn254Fp12Sqr(t, "_wafe_b2", "_wafe_b4")
	bn254Fp12Mul(t, "_wafe_b4", "_wafe_b2_for_b6", "_wafe_b6_core")
	bn254Fp12Sqr(t, "_wafe_b6_core", "_wafe_b12_p0")

	bn254Fp12CopyPrefix(t, "_wa_c", "_wafe_c_w1")
	bn254Fp12Sqr(t, "_wafe_c_w1", "_wafe_c2")
	bn254Fp12CopyPrefix(t, "_wafe_c2", "_wafe_c2_for_c6")
	bn254Fp12Sqr(t, "_wafe_c2", "_wafe_c4")
	bn254Fp12Mul(t, "_wafe_c4", "_wafe_c2_for_c6", "_wafe_c6")
	bn254Fp12Sqr(t, "_wafe_c6", "_wafe_c12_p0")

	bn254Fp12RenamePrefix(t, "_wafe_f2", "_wafe_f2_for_P0")

	// P0 = f2 · a^6 · b^12 · c^12
	bn254Fp12Mul(t, "_wafe_f2_for_P0", "_wafe_a6_p0", "_wafe_P0_s1")
	bn254Fp12Mul(t, "_wafe_P0_s1", "_wafe_b12_p0", "_wafe_P0_s2")
	bn254Fp12Mul(t, "_wafe_P0_s2", "_wafe_c12_p0", "_wafe_P0")

	// Drop the witnesses still on the stack (_wa_a, _wa_b, _wa_c copies).
	bn254Fp12DropInputs(t, "_wa_a")
	bn254Fp12DropInputs(t, "_wa_b")
	bn254Fp12DropInputs(t, "_wa_c")

	// Reduce P0 components and bring to top.
	for _, part := range []string{"_a", "_b"} {
		for i := 0; i < 3; i++ {
			sfx := string(rune('0' + i))
			bn254FieldMod(t, "_wafe_P0"+part+"_"+sfx+"_0", "_wafe_P0"+part+"_"+sfx+"_0_r")
			bn254FieldMod(t, "_wafe_P0"+part+"_"+sfx+"_1", "_wafe_P0"+part+"_"+sfx+"_1_r")
		}
	}
	for _, part := range []string{"_a", "_b"} {
		for i := 0; i < 3; i++ {
			sfx := string(rune('0' + i))
			t.toTop("_wafe_P0" + part + "_" + sfx + "_0_r")
			t.toTop("_wafe_P0" + part + "_" + sfx + "_1_r")
		}
	}

	t.PopPrimeCache()
}

// EmitWAFinalExpResultDebug is a debugging variant of EmitWAFinalExpStandalone
// that leaves the 12-Fp-slot result on top of stack (in prefix order
// _result_a_0_0 ... _result_b_2_1) instead of running IsOne. This lets
// callers compare the raw result against gnark.FinalExponentiation's output
// component-wise, which gives a much more informative failure than a boolean.
//
// Stack layout expected: same 60 Fp slots as EmitWAFinalExpStandalone.
// Stack out: 12 Fp slots for the final exponentiation result.
func EmitWAFinalExpResultDebug(emit func(StackOp)) {
	initNames := []string{}
	for _, prefix := range []string{"_f", "_wa_finv", "_wa_a", "_wa_b", "_wa_c"} {
		for _, part := range []string{"_a", "_b"} {
			for i := 0; i < 3; i++ {
				sfx := string(rune('0' + i))
				initNames = append(initNames, prefix+part+"_"+sfx+"_0")
				initNames = append(initNames, prefix+part+"_"+sfx+"_1")
			}
		}
	}
	t := NewBN254Tracker(initNames, emit)
	t.PushPrimeCache()
	emitWAFinalExp(t, "_f", "_result")
	// Reduce each _result component mod p for canonical comparison.
	for _, part := range []string{"_a", "_b"} {
		for i := 0; i < 3; i++ {
			sfx := string(rune('0' + i))
			bn254FieldMod(t, "_result"+part+"_"+sfx+"_0", "_result"+part+"_"+sfx+"_0_r")
			bn254FieldMod(t, "_result"+part+"_"+sfx+"_1", "_result"+part+"_"+sfx+"_1_r")
		}
	}
	// Bring the reduced result to the top in prefix order (a_0_0 deepest).
	for _, part := range []string{"_a", "_b"} {
		for i := 0; i < 3; i++ {
			sfx := string(rune('0' + i))
			t.toTop("_result" + part + "_" + sfx + "_0_r")
			t.toTop("_result" + part + "_" + sfx + "_1_r")
		}
	}
	t.PopPrimeCache()
}

// EmitWAFinalExpStandalone emits a script that runs just the witness-assisted
// final exponentiation on inputs already present on the stack.
//
// Stack layout expected (deepest → top):
//
//	_f_a_0_0, _f_a_0_1, _f_a_1_0, _f_a_1_1, _f_a_2_0, _f_a_2_1,
//	_f_b_0_0, _f_b_0_1, _f_b_1_0, _f_b_1_1, _f_b_2_0, _f_b_2_1,    (12 slots for f)
//	_wa_finv_*                                                      (12 slots for f⁻¹)
//	_wa_a_*                                                         (12 slots for a)
//	_wa_b_*                                                         (12 slots for b)
//	_wa_c_*                                                         (12 slots for c)
//
// 60 Fp values total. After the script runs, a single boolean is left on
// top indicating whether the final exponentiation result equals the Fp12
// identity (1). Callers can OP_VERIFY that boolean to assert the result.
//
// Used by package-level tests in compilers/go/codegen and by executable
// tests in packages/runar-go/bn254witness that feed real gnark-computed
// inputs through the full witness-assisted final exp and compare the
// boolean output to gnark.FinalExponentiation's result (encoded as "is it
// the identity?" via pre-multiplying by the inverse of gnark's result).
func EmitWAFinalExpStandalone(emit func(StackOp)) {
	initNames := []string{}
	for _, prefix := range []string{"_f", "_wa_finv", "_wa_a", "_wa_b", "_wa_c"} {
		for _, part := range []string{"_a", "_b"} {
			for i := 0; i < 3; i++ {
				sfx := string(rune('0' + i))
				initNames = append(initNames, prefix+part+"_"+sfx+"_0")
				initNames = append(initNames, prefix+part+"_"+sfx+"_1")
			}
		}
	}
	t := NewBN254Tracker(initNames, emit)
	t.PushPrimeCache()
	emitWAFinalExp(t, "_f", "_result")
	// Leave bn254Fp12IsOne boolean on top so the caller can OP_VERIFY.
	bn254Fp12IsOne(t, "_result", "_check")
	t.PopPrimeCache()
}

// =========================================================================
// Utility
// =========================================================================

// itoa is defined in sha256.go (shared across the package).

// CountMillerLoopIterations returns the number of iterations in the BN254
// Miller loop NAF. Useful for allocating witness gradients.
func CountMillerLoopIterations() (totalIters int, additionSteps int) {
	naf := bn254SixXPlus2NAF
	msbIdx := len(naf) - 1
	for msbIdx > 0 && naf[msbIdx] == 0 {
		msbIdx--
	}

	for i := msbIdx - 1; i >= 0; i-- {
		totalIters++
		if naf[i] != 0 {
			additionSteps++
		}
	}
	return
}

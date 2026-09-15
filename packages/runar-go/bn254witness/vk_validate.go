package bn254witness

import (
	"fmt"
	"math/big"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
)

// fpModulus is the BN254 base field modulus p. Cached once; never mutated.
var fpModulus = fp.Modulus()

// Validate checks that a VerifyingKey's own points are usable as a Groth16
// verifying key on BN254. It is called by LoadSP1VKFromFile, and is exported
// so that callers who build a VerifyingKey by other means (literal struct,
// NewVerifyingKeyFromPositive, a bespoke deserialiser) can apply the same bar.
//
// WHAT IS ENFORCED
//
//   - Canonical coordinates. Every coordinate must be in [0, p). fp.Element's
//     SetBigInt silently reduces mod p, so a coordinate of x+p would pass every
//     curve check while VerifyingKey (and therefore the script pushdata the
//     compiler bakes in, which uses the raw *big.Int) carried the non-reduced
//     value. Rejecting non-canonical input keeps "what gnark validated" and
//     "what goes on chain" the same number.
//
//   - Non-degeneracy of α, -β, -γ, -δ. The point at infinity, encoded (0,0)
//     here, makes its pairing factor the identity: e(L, O) = 1 for every L, so
//     a zero -γ drops the public-input term out of
//     e(A,B)·e(L,-γ)·e(C,-δ)·e(α,-β) = 1 entirely, and a zero -δ drops the
//     proof's C term. That is the exact shape R-159 names.
//
//   - On-curve. y² = x³ + 3 for G1; y² = x³ + 3/(9+u) over Fp2 for the G2
//     twist. A coordinate pair that is not on its curve is not a key; it also
//     lives in a group whose order is unrelated to r, which is what makes the
//     witness-assisted gradient equations forgeable. This mirrors the standard
//     already applied to every PROVER-supplied point by
//     compilers/go/codegen/bn254_groth16.go (emitWAG1OnCurveCheck /
//     emitWAG2OnCurveCheck), which the VK's own points previously escaped.
//
//   - Prime-order subgroup for the G2 points. E'(Fp2) has a large cofactor, so
//     on-curve does NOT imply order r on G2: an on-curve point of small order
//     admits the classic small-subgroup attack. gnark's G2Affine.IsInSubGroup
//     implements the ψ-endomorphism test of eprint 2022/348 §3; it costs one
//     scalar multiplication per point, three times, once at load. For G1 the
//     BN254 cofactor is 1 (E(Fp) has order exactly r), so on-curve already
//     implies subgroup membership and gnark's G1 IsInSubGroup is literally
//     IsOnCurve — no separate call is made.
//
// WHAT IS DELIBERATELY NOT ENFORCED
//
//   - That α, β, γ, δ are the discrete logs produced by the circuit's trusted
//     setup, or that IC corresponds to this circuit. No local check can decide
//     that; it is a property of the setup ceremony and of whoever hands you the
//     file. Everything here rules out malformed keys, not wrong ones.
//
//   - IC entries at infinity. An IC column of (0,0) means that public input has
//     no effect on the verification equation. That is a red flag, but it is
//     mathematically legal for a circuit whose public-input wire is unused, so
//     rejecting it would refuse a valid production key. IC entries are held to
//     canonical-coordinate and on-curve only. (Separately, the compiler-side
//     config builder pads IC to six entries with (0,0) of its own accord —
//     compilers/go/compiler/groth16_wa.go — which is why forbidding it here
//     would buy nothing anyway.)
//
//   - Any relation BETWEEN points (γ ≠ δ, α ≠ O, distinctness of IC entries).
//     A correct setup makes collisions negligible and none of them is a
//     soundness break the loader can adjudicate.
func (vk VerifyingKey) Validate() error {
	if err := validateVKG1(vk.AlphaG1, "alphaG1", false); err != nil {
		return err
	}
	if err := validateVKG2(vk.BetaNegG2, "betaNegG2"); err != nil {
		return err
	}
	if err := validateVKG2(vk.GammaNegG2, "gammaNegG2"); err != nil {
		return err
	}
	if err := validateVKG2(vk.DeltaNegG2, "deltaNegG2"); err != nil {
		return err
	}
	if len(vk.IC) == 0 {
		return fmt.Errorf("ic: verifying key carries no IC points")
	}
	for i, p := range vk.IC {
		if p == nil {
			return fmt.Errorf("ic[%d]: missing point", i)
		}
		if err := validateVKG1(*p, fmt.Sprintf("ic[%d]", i), true); err != nil {
			return err
		}
	}
	return nil
}

// validateVKCoord rejects nil, negative, and non-canonical (>= p) coordinates.
func validateVKCoord(v *big.Int, field, coord string) error {
	if v == nil {
		return fmt.Errorf("%s.%s: missing coordinate", field, coord)
	}
	if v.Sign() < 0 {
		return fmt.Errorf("%s.%s: negative coordinate %s", field, coord, v)
	}
	if v.Cmp(fpModulus) >= 0 {
		return fmt.Errorf(
			"%s.%s: coordinate %s is not canonical (>= the BN254 base field modulus p); "+
				"it would be silently reduced mod p by the curve checks while the raw value "+
				"is what gets baked into the script",
			field, coord, v,
		)
	}
	return nil
}

// validateVKG1 checks one G1 point. allowInfinity permits the (0,0) encoding
// of the identity — true only for IC entries, see Validate's doc comment.
func validateVKG1(p [2]*big.Int, field string, allowInfinity bool) error {
	if err := validateVKCoord(p[0], field, "x"); err != nil {
		return err
	}
	if err := validateVKCoord(p[1], field, "y"); err != nil {
		return err
	}

	var g bn254.G1Affine
	g.X.SetBigInt(p[0])
	g.Y.SetBigInt(p[1])

	// gnark maps the (0,0) encoding to Z=0 in Jacobian coordinates, for which
	// IsOnCurve is vacuously true — so infinity must be tested separately.
	if g.IsInfinity() {
		if allowInfinity {
			return nil
		}
		return fmt.Errorf(
			"%s: point at infinity (0,0); its pairing factor is the identity, "+
				"which drops the term out of the Groth16 equation", field)
	}
	if !g.IsOnCurve() {
		return fmt.Errorf("%s: (%s, %s) is not on the BN254 G1 curve", field, p[0], p[1])
	}
	// BN254 G1 has cofactor 1, so on-curve implies order r. No subgroup call.
	return nil
}

// validateVKG2 checks one G2 point: canonical coordinates, not infinity, on the
// twist curve, and in the prime-order subgroup.
func validateVKG2(p [4]*big.Int, field string) error {
	for i, coord := range [4]string{"x0", "x1", "y0", "y1"} {
		if err := validateVKCoord(p[i], field, coord); err != nil {
			return err
		}
	}

	var q bn254.G2Affine
	q.X.A0.SetBigInt(p[0])
	q.X.A1.SetBigInt(p[1])
	q.Y.A0.SetBigInt(p[2])
	q.Y.A1.SetBigInt(p[3])

	if q.IsInfinity() {
		return fmt.Errorf(
			"%s: point at infinity (0,0,0,0); its pairing factor is the identity, "+
				"which drops the term out of the Groth16 equation", field)
	}
	if !q.IsOnCurve() {
		return fmt.Errorf(
			"%s: (%s, %s, %s, %s) is not on the BN254 G2 twist curve",
			field, p[0], p[1], p[2], p[3])
	}
	if !q.IsInSubGroup() {
		return fmt.Errorf(
			"%s: on the twist curve but outside the prime-order (r) subgroup; "+
				"small-subgroup points are not valid verifying-key material", field)
	}
	return nil
}

package bn254witness

import (
	"fmt"
	"math/big"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// computePreparedInputs computes the Groth16 public-input accumulator:
//
//	prepared_inputs = IC[0] + sum_{j=0}^{n-1} publicInputs[j] * IC[j+1]
//
// using gnark-crypto's G1 arithmetic. The returned point is in Rúnar
// [x, y] order.
//
// This helper replaces the previous on-chain witness-assisted MSM: because
// gnark-crypto's G1Affine.Add handles the identity case natively, zero
// public inputs work with no special casing:
//   - pub_j = 0 produces W_j = identity, which is the additive unit (noop).
//   - Repeated IC points are fine (doubling is handled internally).
//   - An identity result is representable (though for a valid VK the final
//     prepared_inputs is never the identity point).
//
// The on-chain verifier now simply on-curve-checks this point and uses it
// as the G1 input for the second pairing — matching how SP1's Solidity
// verifier computes the MSM via the BN254 EC precompile.
//
// Per user decision R86a (N-035), the on-chain witness-assisted MSM binding
// asserts 0 <= pub_i < r for each public input before folding it into the
// accumulator — a non-canonical representative (pub_i + k*r, pub_i - r, ...)
// would bind the SAME accumulator as its canonical residue while the
// contract body and the txid see the raw, unreduced value. This helper
// refuses such inputs instead of silently reducing them mod r (N-232), so
// callers learn about the mismatch at build time instead of a rejected
// on-chain spend.
func computePreparedInputs(ic []*[2]*big.Int, publicInputs []*big.Int) ([2]*big.Int, error) {
	if err := validatePublicInputsCanonical(publicInputs); err != nil {
		return [2]*big.Int{}, err
	}
	return computePreparedInputsUnchecked(ic, publicInputs)
}

// validatePublicInputsCanonical returns an error if any scalar in
// publicInputs is outside the canonical range [0, r) for the BN254 scalar
// field (r = fr.Modulus()). Negative values and values >= r are both
// rejected.
func validatePublicInputsCanonical(publicInputs []*big.Int) error {
	r := fr.Modulus()
	for i, pub := range publicInputs {
		if pub.Sign() < 0 || pub.Cmp(r) >= 0 {
			return fmt.Errorf(
				"public input %d is not a canonical BN254 Fr element: %s is outside [0, %s)",
				i, pub.String(), r.String(),
			)
		}
	}
	return nil
}

// computePreparedInputsUnchecked is computePreparedInputs without the
// canonicity check on publicInputs. It exists ONLY so that
// BuildFromProofWithInputsUnchecked (test-only, see its doc comment) can
// construct the adversarial witness that the on-chain MSM-binding preamble
// (N-035, R86a) must reject — proving the SCRIPT rejects it, not the SDK.
// Do not call this outside tests; production code must go through
// computePreparedInputs / BuildFromProofWithInputs, which refuse
// non-canonical inputs.
func computePreparedInputsUnchecked(ic []*[2]*big.Int, publicInputs []*big.Int) ([2]*big.Int, error) {
	if len(ic) != len(publicInputs)+1 {
		return [2]*big.Int{}, fmt.Errorf(
			"computePreparedInputs: ic length %d != publicInputs length %d + 1",
			len(ic), len(publicInputs),
		)
	}

	// Convert IC[0] to gnark G1Affine. IC[0] is the unconditional baseline —
	// it's the starting accumulator (no scalar multiplied).
	acc, err := bigPairToG1Affine(ic[0])
	if err != nil {
		return [2]*big.Int{}, fmt.Errorf("ic[0]: %w", err)
	}

	for j, scalar := range publicInputs {
		// Skip zero inputs: 0 * IC = identity, which is the additive unit
		// and does not change the accumulator. gnark-crypto's Add handles
		// identity correctly, but skipping is faster and keeps the
		// accumulator math free of the degenerate case.
		if scalar.Sign() == 0 {
			continue
		}

		base, err := bigPairToG1Affine(ic[j+1])
		if err != nil {
			return [2]*big.Int{}, fmt.Errorf("ic[%d]: %w", j+1, err)
		}

		// Reduce the scalar mod r so gnark's ScalarMultiplication sees a
		// normalised value (inputs from SP1 are already reduced, but we
		// do it defensively).
		var s fr.Element
		s.SetBigInt(scalar)
		var sBig big.Int
		s.BigInt(&sBig)

		var w bn254.G1Affine
		w.ScalarMultiplication(&base, &sBig)

		// acc = acc + w. gnark's G1Affine.Add handles the identity and
		// doubling cases internally.
		var sum bn254.G1Affine
		sum.Add(&acc, &w)
		acc = sum
	}

	// Return final accumulator as Rúnar [x, y].
	var accxBig, accyBig big.Int
	acc.X.BigInt(&accxBig)
	acc.Y.BigInt(&accyBig)
	return [2]*big.Int{
		new(big.Int).Set(&accxBig),
		new(big.Int).Set(&accyBig),
	}, nil
}

// bigPairToG1Affine converts [2]*big.Int (x, y) to a gnark G1Affine. Returns
// an error if the resulting point is not on the curve.
func bigPairToG1Affine(p *[2]*big.Int) (bn254.G1Affine, error) {
	var g bn254.G1Affine
	g.X.SetBigInt(p[0])
	g.Y.SetBigInt(p[1])
	if !g.IsOnCurve() {
		return g, fmt.Errorf("point (%s, %s) is not on BN254 G1", p[0], p[1])
	}
	return g, nil
}

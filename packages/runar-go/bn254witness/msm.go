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
func computePreparedInputs(ic []*[2]*big.Int, publicInputs []*big.Int) ([2]*big.Int, error) {
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

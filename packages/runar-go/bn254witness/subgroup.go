package bn254witness

import (
	"fmt"
	"math/big"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"

	"github.com/icellan/runar/compilers/go/codegen"
)

// computeSubgroupGradients runs the off-chain mirror of
// emitWAG2FixedScalarMul: given a G2 point P it emits the slope witnesses
// λ (Fp2) for each doubling and each addition in the left-to-right
// double-and-add expansion of the fixed scalar 6·x² (x = BN254 seed).
//
// The gradients are flattened as [d0_re, d0_im, d1_re, d1_im, ..., dN-1_im,
// a0_re, a0_im, a1_re, a1_im, ..., aM-1_im], which is the same order
// appendSubgroupGradientNames declares in the on-chain initNames and the
// same order the unlocking script must push them (deepest first).
//
// Returns an error when an intermediate step would require a division by
// zero in Fp2 — i.e. when the supplied P is not in the prime-order
// subgroup and the chain runs through an identity point mid-way. For
// honest G2 inputs this never triggers; for a hostile prover the resulting
// Witness is unusable, which is the desired behaviour — the on-chain
// verifier aborts on missing gradients the same way.
func computeSubgroupGradients(proofB [4]*big.Int) ([]*big.Int, error) {
	k := codegen.Bn254SubgroupCheckScalar()
	if k.Sign() <= 0 {
		return nil, fmt.Errorf("bn254witness: subgroup check scalar is non-positive")
	}

	P, err := toAffineG2(proofB)
	if err != nil {
		return nil, fmt.Errorf("bn254witness: subgroup: parse G2 point: %w", err)
	}

	nbits := k.BitLen()
	// Left-to-right double-and-add: T = P (consuming the MSB), then for
	// each subsequent bit double T and, if the bit is 1, add P.
	T := P

	nD, nA := codegen.Bn254SubgroupCheckGradientCount()
	doublings := make([]bn254.E2, 0, nD)
	additions := make([]bn254.E2, 0, nA)

	for i := nbits - 2; i >= 0; i-- {
		// Doubling: λ_d = 3·Tx² / (2·Ty). Hard-fails the off-chain
		// computation if Ty = 0 (point-at-infinity case); the emit-side
		// gradient check would also abort on such a point, so returning
		// an error here matches the on-chain soundness boundary.
		lamD, newT, err := doubleG2WithLambda(T)
		if err != nil {
			return nil, fmt.Errorf("bn254witness: subgroup doubling %d: %w", len(doublings), err)
		}
		doublings = append(doublings, lamD)
		T = newT

		if k.Bit(i) == 1 {
			// Addition T = T + P: λ_a = (Py - Ty)/(Px - Tx). Fails if
			// Tx == Px (mid-chain collision with the base point).
			lamA, newT, err := addG2WithLambda(T, P)
			if err != nil {
				return nil, fmt.Errorf("bn254witness: subgroup addition %d: %w", len(additions), err)
			}
			additions = append(additions, lamA)
			T = newT
		}
	}

	out := make([]*big.Int, 0, (len(doublings)+len(additions))*2)
	for _, lam := range doublings {
		out = append(out, fp2ToFlat(lam)...)
	}
	for _, lam := range additions {
		out = append(out, fp2ToFlat(lam)...)
	}
	return out, nil
}

// doubleG2WithLambda computes (λ, 2T) for T in affine coordinates. Errors
// when T.y = 0 (point of order 2; infinite slope), which is the only Fp2
// state that would require special-case handling in the witness-assisted
// gradient formula λ·(2·Ty) == 3·Tx².
func doubleG2WithLambda(T affineG2) (bn254.E2, affineG2, error) {
	var zero bn254.E2
	if T.Y.Equal(&zero) {
		return bn254.E2{}, affineG2{}, fmt.Errorf("point at infinity / 2-torsion encountered in G2 doubling")
	}

	var num bn254.E2
	num.Square(&T.X)
	var three fp.Element
	three.SetUint64(3)
	num.A0.Mul(&num.A0, &three)
	num.A1.Mul(&num.A1, &three)

	var den bn254.E2
	den.Double(&T.Y)

	var denInv bn254.E2
	denInv.Inverse(&den)
	var lambda bn254.E2
	lambda.Mul(&num, &denInv)

	var lambdaSq bn254.E2
	lambdaSq.Square(&lambda)
	var twoTx bn254.E2
	twoTx.Double(&T.X)
	var newX bn254.E2
	newX.Sub(&lambdaSq, &twoTx)

	var diff bn254.E2
	diff.Sub(&T.X, &newX)
	var lProd bn254.E2
	lProd.Mul(&lambda, &diff)
	var newY bn254.E2
	newY.Sub(&lProd, &T.Y)

	return lambda, affineG2{X: newX, Y: newY}, nil
}

// addG2WithLambda computes (λ, T+Q) for distinct affine G2 points T, Q.
// Errors when Q.x == T.x (either T == Q, requiring doubling, or T == -Q,
// giving the point at infinity). Both cases indicate a mid-chain
// degeneracy that the on-chain gradient check also aborts on.
func addG2WithLambda(T, Q affineG2) (bn254.E2, affineG2, error) {
	if T.X.Equal(&Q.X) {
		return bn254.E2{}, affineG2{}, fmt.Errorf("x-collision in G2 addition")
	}
	var num bn254.E2
	num.Sub(&Q.Y, &T.Y)
	var den bn254.E2
	den.Sub(&Q.X, &T.X)

	var denInv bn254.E2
	denInv.Inverse(&den)
	var lambda bn254.E2
	lambda.Mul(&num, &denInv)

	var lambdaSq bn254.E2
	lambdaSq.Square(&lambda)
	var sub1 bn254.E2
	sub1.Sub(&lambdaSq, &T.X)
	var newX bn254.E2
	newX.Sub(&sub1, &Q.X)

	var diff bn254.E2
	diff.Sub(&T.X, &newX)
	var lProd bn254.E2
	lProd.Mul(&lambda, &diff)
	var newY bn254.E2
	newY.Sub(&lProd, &T.Y)

	return lambda, affineG2{X: newX, Y: newY}, nil
}

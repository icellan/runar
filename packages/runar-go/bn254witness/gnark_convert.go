package bn254witness

import (
	"math/big"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
)

// GnarkVKToWitnessInputs converts a gnark-crypto bn254.G1Affine /
// bn254.G2Affine VK into the bn254witness.VerifyingKey type.
//
// The input G2 values are EXPECTED PRE-NEGATED: β, γ, δ are treated as
// raw values that will be stored verbatim in BetaNegG2, GammaNegG2,
// DeltaNegG2. Use this helper when you already have -β, -γ, -δ (e.g.
// reading SP1 VK constants). If you have POSITIVE β, γ, δ and want the
// negation done for you, call NewVerifyingKeyFromPositive instead.
//
// Why these arguments instead of taking a gnark/backend/groth16 VerifyingKey
// directly? Because that import pulls in a large transitive test-dependency
// graph that can conflict with our pinned gnark-crypto version. By accepting
// gnark-crypto's lower-level types directly, we keep this package's dep
// surface minimal — callers extract VK fields using their own gnark version.
//
// Both Gnark's Go API and Rúnar use (real, imag) order for Fp2 components
// (gnark E2 = {A0=real, A1=imag}). No swap is required when going through
// the Go API. A swap IS required when reading from a SERIALIZED gnark VK
// (Solidity ABI / Marshal()) — that's handled by ParseSP1RawProof.
func GnarkVKToWitnessInputs(
	alphaG1 bn254.G1Affine,
	betaNegG2 bn254.G2Affine,
	gammaNegG2 bn254.G2Affine,
	deltaNegG2 bn254.G2Affine,
	icG1 []bn254.G1Affine,
) VerifyingKey {
	vk := VerifyingKey{
		AlphaG1:    G1AffineToBig(alphaG1),
		BetaNegG2:  G2AffineToBig(betaNegG2),
		GammaNegG2: G2AffineToBig(gammaNegG2),
		DeltaNegG2: G2AffineToBig(deltaNegG2),
		IC:         make([]*[2]*big.Int, len(icG1)),
	}
	for i, p := range icG1 {
		pair := G1AffineToBig(p)
		vk.IC[i] = &pair
	}
	return vk
}

// NewVerifyingKeyFromPositive constructs a VerifyingKey from POSITIVE
// α, β, γ, δ gnark G2 values — it negates β, γ, δ internally so callers
// don't have to remember the SP1 convention. This is the most ergonomic
// entry point for synthetic tests that build the VK out of positive
// generator multiples.
//
// For raw SP1 VK constants (where -β, -γ, -δ are already stored on the
// host side), use GnarkVKToWitnessInputs instead.
func NewVerifyingKeyFromPositive(
	alphaG1 bn254.G1Affine,
	betaG2 bn254.G2Affine,
	gammaG2 bn254.G2Affine,
	deltaG2 bn254.G2Affine,
	icG1 []bn254.G1Affine,
) VerifyingKey {
	var negBeta, negGamma, negDelta bn254.G2Affine
	negBeta.Neg(&betaG2)
	negGamma.Neg(&gammaG2)
	negDelta.Neg(&deltaG2)
	return GnarkVKToWitnessInputs(alphaG1, negBeta, negGamma, negDelta, icG1)
}

// GnarkProofToWitnessInputs converts gnark-crypto Groth16 proof points
// (Ar, Bs, Krs) into the bn254witness.Proof type.
func GnarkProofToWitnessInputs(ar bn254.G1Affine, bs bn254.G2Affine, krs bn254.G1Affine) Proof {
	return Proof{
		A: G1AffineToBig(ar),
		B: G2AffineToBig(bs),
		C: G1AffineToBig(krs),
	}
}

// G1AffineToBig converts a bn254.G1Affine into [x, y] *big.Int.
func G1AffineToBig(p bn254.G1Affine) [2]*big.Int {
	x := new(big.Int)
	p.X.BigInt(x)
	y := new(big.Int)
	p.Y.BigInt(y)
	return [2]*big.Int{x, y}
}

// G2AffineToBig converts a bn254.G2Affine into [x0, x1, y0, y1] *big.Int
// in Rúnar (real, imag) order. gnark stores E2 as {A0, A1} where A0 is the
// real part, so this is a direct read with no swap.
func G2AffineToBig(p bn254.G2Affine) [4]*big.Int {
	x0 := new(big.Int)
	p.X.A0.BigInt(x0)
	x1 := new(big.Int)
	p.X.A1.BigInt(x1)
	y0 := new(big.Int)
	p.Y.A0.BigInt(y0)
	y1 := new(big.Int)
	p.Y.A1.BigInt(y1)
	return [4]*big.Int{x0, x1, y0, y1}
}

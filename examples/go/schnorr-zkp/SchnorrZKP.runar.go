package contract

import runar "github.com/icellan/runar/packages/runar-go"

// SchnorrZKP verifies a Schnorr zero-knowledge proof (non-interactive, Fiat-Shamir).
//
// Proves knowledge of a private key k such that P = k*G without revealing k.
// Uses the Schnorr identification protocol with the Fiat-Shamir heuristic
// to derive the challenge on-chain:
//
//	Prover: picks random r, computes R = r*G
//	Challenge: e = Bin2Num(Hash256(R || P))  (derived on-chain)
//	Prover: sends s = r + e*k (mod n)
//	Verifier: checks s*G === R + e*P
//
// The challenge is derived deterministically from the commitment and
// public key, preventing the prover from choosing a convenient e.
type SchnorrZKP struct {
	runar.SmartContract
	// PubKey is the verifier's public key P = k*G (64-byte uncompressed Point).
	PubKey runar.Point `runar:"readonly"`
}

// Verify checks a Schnorr ZKP proof.
//
// rPoint is the commitment R = r*G (prover's nonce point).
// s is the response s = r + e*k (mod n).
func (c *SchnorrZKP) Verify(rPoint runar.Point, s runar.Bigint) {
	// Verify R is on the curve
	runar.Assert(runar.EcOnCurve(rPoint))

	// Derive challenge via Fiat-Shamir: e = Bin2Num(Hash256(R || P))
	e := runar.Bin2Num(runar.Hash256(runar.Cat(rPoint, c.PubKey)))

	// Left side: s*G
	sG := runar.EcMulGen(s)

	// Right side: R + e*P
	eP := runar.EcMul(c.PubKey, e)
	rhs := runar.EcAdd(rPoint, eP)

	// Verify equality
	runar.Assert(runar.EcPointX(sG) == runar.EcPointX(rhs))
	runar.Assert(runar.EcPointY(sG) == runar.EcPointY(rhs))
}

package contract

import runar "github.com/icellan/runar/packages/runar-go"

// SchnorrZKP verifies a Schnorr zero-knowledge proof.
//
// Proves knowledge of a private key k such that P = k*G without revealing k.
// Uses the Schnorr identification protocol:
//
//	Prover: picks random r, sends R = r*G
//	Verifier: sends challenge e
//	Prover: sends s = r + e*k (mod n)
//	Verifier: checks s*G === R + e*P
//
// In a Bitcoin contract context, the prover provides (R, s, e) in the
// unlocking script, and the contract verifies the proof on-chain.
type SchnorrZKP struct {
	runar.SmartContract
	PubKey runar.Point `runar:"readonly"`
}

// Verify checks a Schnorr ZKP proof.
//
// rPoint is the commitment R = r*G (prover's nonce point).
// s is the response s = r + e*k (mod n).
// e is the challenge value.
func (c *SchnorrZKP) Verify(rPoint runar.Point, s runar.Bigint, e runar.Bigint) {
	// Verify R is on the curve
	runar.Assert(runar.EcOnCurve(rPoint))

	// Left side: s*G
	sG := runar.EcMulGen(s)

	// Right side: R + e*P
	eP := runar.EcMul(c.PubKey, e)
	rhs := runar.EcAdd(rPoint, eP)

	// Verify equality
	runar.Assert(runar.EcPointX(sG) == runar.EcPointX(rhs))
	runar.Assert(runar.EcPointY(sG) == runar.EcPointY(rhs))
}

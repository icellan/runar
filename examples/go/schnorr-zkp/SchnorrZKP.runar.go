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
type SchnorrZKP struct {
	runar.SmartContract
	PubKey runar.Point `runar:"readonly"`
}

// Verify checks a Schnorr ZKP proof.
func (c *SchnorrZKP) Verify(rPoint runar.Point, s runar.Bigint, e runar.Bigint) {
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

package contract

import runar "github.com/icellan/runar/packages/runar-go"

// ConvergenceProof verifies OPRF-based fraud signal convergence.
//
// Two parties submit randomized tokens R_A = (T + o_A)*G and R_B = (T + o_B)*G
// where T is the shared underlying token and o_A, o_B are ECDH-derived offsets.
//
// An authority who knows both offsets can prove the two submissions share the
// same token T by providing Δo = o_A - o_B and verifying:
//
//	R_A - R_B = Δo · G
//
// The token T cancels out in the subtraction, proving convergence without
// revealing T. Spending this UTXO serves as a formal on-chain subpoena trigger.
type ConvergenceProof struct {
	runar.SmartContract
	RA runar.Point `runar:"readonly"`
	RB runar.Point `runar:"readonly"`
}

// ProveConvergence verifies convergence via offset difference.
//
// deltaO is the offset difference o_A - o_B (mod n), provided by the authority.
func (c *ConvergenceProof) ProveConvergence(deltaO runar.Bigint) {
	// Verify both committed points are on the curve
	runar.Assert(runar.EcOnCurve(c.RA))
	runar.Assert(runar.EcOnCurve(c.RB))

	// R_A - R_B (point subtraction = add + negate)
	diff := runar.EcAdd(c.RA, runar.EcNegate(c.RB))

	// Δo · G (scalar multiplication of generator)
	expected := runar.EcMulGen(deltaO)

	// Assert point equality via coordinate comparison
	runar.Assert(runar.EcPointX(diff) == runar.EcPointX(expected))
	runar.Assert(runar.EcPointY(diff) == runar.EcPointY(expected))
}

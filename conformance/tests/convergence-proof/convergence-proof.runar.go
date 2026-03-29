package contract

import "runar"

type ConvergenceProof struct {
	runar.SmartContract
	RA runar.Point `runar:"readonly"`
	RB runar.Point `runar:"readonly"`
}

func (c *ConvergenceProof) ProveConvergence(deltaO runar.Bigint) {
	// Verify both committed points are on the curve
	runar.Assert(runar.EcOnCurve(c.RA))
	runar.Assert(runar.EcOnCurve(c.RB))

	// R_A - R_B (point subtraction = add + negate)
	diff := runar.EcAdd(c.RA, runar.EcNegate(c.RB))

	// delta_o * G (scalar multiplication of generator)
	expected := runar.EcMulGen(deltaO)

	// Assert point equality via coordinate comparison
	runar.Assert(runar.EcPointX(diff) == runar.EcPointX(expected))
	runar.Assert(runar.EcPointY(diff) == runar.EcPointY(expected))
}

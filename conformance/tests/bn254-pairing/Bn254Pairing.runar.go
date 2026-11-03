package contract

import runar "github.com/icellan/runar/packages/runar-go"

// Bn254Pairing -- N-314: four-pair BN254 pairing-product check (Go-only
// codegen). Asserts e(p1,q1)·e(p2,q2)·e(p3,q3)·e(p4,q4) == 1 in GT.
type Bn254Pairing struct {
	runar.SmartContract
}

func (c *Bn254Pairing) Verify(
	p1 runar.Point, q1x0, q1x1, q1y0, q1y1 runar.Bigint,
	p2 runar.Point, q2x0, q2x1, q2y0, q2y1 runar.Bigint,
	p3 runar.Point, q3x0, q3x1, q3y0, q3y1 runar.Bigint,
	p4 runar.Point, q4x0, q4x1, q4y0, q4y1 runar.Bigint,
) {
	runar.Assert(runar.Bn254MultiPairing4(
		p1, q1x0, q1x1, q1y0, q1y1,
		p2, q2x0, q2x1, q2y0, q2y1,
		p3, q3x0, q3x1, q3y0, q3y1,
		p4, q4x0, q4x1, q4y0, q4y1,
	))
}

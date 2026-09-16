package contract

import runar "github.com/icellan/runar/packages/runar-go"

// LoopShapes — Go port. A NON-ZERO loop start, ascending (R-102).
type LoopShapes struct {
	runar.SmartContract
	Target runar.Int `runar:"readonly"`
}

func (c *LoopShapes) Verify(seed runar.Int) {
	acc := seed
	for i := runar.Int(3); i < 7; i++ {
		acc = acc + i
	}
	runar.Assert(acc == c.Target)
}

//go:build ignore

package contract

import "runar"

// LoopShapes — Go port. Non-zero loop start plus a countdown loop (R-102).
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

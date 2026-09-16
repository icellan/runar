//go:build ignore

package contract

import "runar"

// CountdownLoop — Go port. `step = -1` (R-102).
// See CountdownLoop.runar.ts for what the missing descending fixture hid.
type CountdownLoop struct {
	runar.SmartContract
	Target runar.Int `runar:"readonly"`
}

func (c *CountdownLoop) Verify(seed runar.Int) {
	acc := seed
	for i := runar.Int(5); i > 1; i-- {
		acc = acc + i
	}
	runar.Assert(acc == c.Target)
}

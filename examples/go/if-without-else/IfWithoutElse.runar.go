//go:build ignore

package contract

import "runar"

type IfWithoutElse struct {
	runar.SmartContract
	Threshold runar.Int `runar:"readonly"`
}

func (c *IfWithoutElse) Check(a runar.Int, b runar.Int) {
	count := runar.Int(0)
	if a > c.Threshold {
		count = count + 1
	}
	if b > c.Threshold {
		count = count + 1
	}
	runar.Assert(count > 0)
}

//go:build ignore

package contract

import "runar"

type IfElse struct {
	runar.SmartContract
	Limit runar.Int `runar:"readonly"`
}

func (c *IfElse) Check(value runar.Int, mode runar.Bool) {
	result := runar.Int(0)
	if mode {
		result = value + c.Limit
	} else {
		result = value - c.Limit
	}
	runar.Assert(result > 0)
}

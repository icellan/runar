//go:build ignore

package contract

import "runar"

type BooleanLogic struct {
	runar.SmartContract
	Threshold runar.Int `runar:"readonly"`
}

func (c *BooleanLogic) Verify(a runar.Int, b runar.Int, flag runar.Bool) {
	aAboveThreshold := a > c.Threshold
	bAboveThreshold := b > c.Threshold
	bothAbove := aAboveThreshold && bAboveThreshold
	eitherAbove := aAboveThreshold || bAboveThreshold
	notFlag := !flag
	runar.Assert(bothAbove || (eitherAbove && notFlag))
}

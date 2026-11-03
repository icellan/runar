package contract

import runar "github.com/icellan/runar/packages/runar-go"

// ShiftOps exercises bitshift operators << and >> on Bigint values.
type ShiftOps struct {
	runar.SmartContract
	A runar.Bigint `runar:"readonly"`
}

// TestShift applies left shift and right shift, then checks the caller-supplied results.
func (c *ShiftOps) TestShift(expectedLeft runar.Bigint, expectedRight runar.Bigint) {
	left := c.A << 3
	right := c.A >> 2
	runar.Assert(left == expectedLeft)
	runar.Assert(right == expectedRight)
}

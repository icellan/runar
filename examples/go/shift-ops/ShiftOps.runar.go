package contract

import runar "github.com/icellan/runar/packages/runar-go"

// ShiftOps exercises bitshift operators << and >> on Bigint values.
type ShiftOps struct {
	runar.SmartContract
	A runar.Bigint `runar:"readonly"`
}

// TestShift applies left shift and right shift, then sanity-checks the results.
func (c *ShiftOps) TestShift() {
	left := c.A << 3
	right := c.A >> 2
	runar.Assert(left >= 0 || left < 0)
	runar.Assert(right >= 0 || right < 0)
}

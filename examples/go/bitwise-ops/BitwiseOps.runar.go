package contract

import runar "github.com/icellan/runar/packages/runar-go"

// BitwiseOps demonstrates bitwise and shift operators on Bigint values.
type BitwiseOps struct {
	runar.SmartContract
	A runar.Bigint `runar:"readonly"`
	B runar.Bigint `runar:"readonly"`
}

// TestShift verifies shift operators compile and run.
func (c *BitwiseOps) TestShift() {
	left := c.A << 2
	right := c.A >> 1
	runar.Assert(left >= 0 || left < 0)
	runar.Assert(right >= 0 || right < 0)
	runar.Assert(true)
}

// TestBitwise verifies bitwise operators compile and run.
func (c *BitwiseOps) TestBitwise() {
	andResult := c.A & c.B
	orResult := c.A | c.B
	xorResult := c.A ^ c.B
	notResult := ^c.A
	runar.Assert(andResult >= 0 || andResult < 0)
	runar.Assert(orResult >= 0 || orResult < 0)
	runar.Assert(xorResult >= 0 || xorResult < 0)
	runar.Assert(notResult >= 0 || notResult < 0)
	runar.Assert(true)
}

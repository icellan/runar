package contract

import runar "github.com/icellan/runar/packages/runar-go"

// BitwiseOps demonstrates bitwise and shift operators on Bigint values.
type BitwiseOps struct {
	runar.SmartContract
	A runar.Bigint `runar:"readonly"`
	B runar.Bigint `runar:"readonly"`
}

// TestShift checks the caller-supplied shift results.
func (c *BitwiseOps) TestShift(expectedLeft runar.Bigint, expectedRight runar.Bigint) {
	left := c.A << 2
	right := c.A >> 1
	runar.Assert(left == expectedLeft)
	runar.Assert(right == expectedRight)
}

// TestBitwise checks the caller-supplied AND/OR/XOR results; ^ (bitwise NOT)
// is checked by double inversion and De Morgan's law (see the TS source for why).
func (c *BitwiseOps) TestBitwise(expectedAnd runar.Bigint, expectedOr runar.Bigint, expectedXor runar.Bigint) {
	andResult := c.A & c.B
	orResult := c.A | c.B
	xorResult := c.A ^ c.B
	notResult := ^c.A
	runar.Assert(andResult == expectedAnd)
	runar.Assert(orResult == expectedOr)
	runar.Assert(xorResult == expectedXor)
	runar.Assert(^notResult == c.A)
	runar.Assert(^(c.A | c.B) == (notResult & ^c.B))
}

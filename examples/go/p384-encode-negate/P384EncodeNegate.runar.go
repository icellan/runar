package contract

import runar "github.com/icellan/runar/packages/runar-go"

// P384EncodeNegate -- Go port. Executed coverage for P384Negate and
// P384EncodeCompressed, neither of which appeared in any fixture.
// See the `.runar.ts` port for the full rationale.
type P384EncodeNegate struct {
	runar.SmartContract
	ExpectedCompressed runar.ByteString `runar:"readonly"`
}

// CheckNegate: (x, y) -> (x, p - y). Guards canonicity AND the 96-byte width.
func (c *P384EncodeNegate) CheckNegate(p runar.P384Point, expected runar.P384Point) {
	n := runar.P384Negate(p)
	runar.Assert(n == expected)
}

// CheckEncode: Point -> 49-byte 02/03||x, parity read at a fixed offset.
func (c *P384EncodeNegate) CheckEncode(p runar.P384Point, expected runar.ByteString) {
	e := runar.P384EncodeCompressed(p)
	runar.Assert(e == expected)
}

// CheckNegateThenEncode: compressing the negation must flip the prefix only.
func (c *P384EncodeNegate) CheckNegateThenEncode(p runar.P384Point) {
	n := runar.P384Negate(p)
	e := runar.P384EncodeCompressed(n)
	runar.Assert(e == c.ExpectedCompressed)
}

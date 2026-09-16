package contract

import runar "github.com/icellan/runar/packages/runar-go"

// P256EncodeNegate -- Go port. Executed coverage for P256Negate and
// P256EncodeCompressed, neither of which appeared in any fixture.
// See the `.runar.ts` port for the full rationale.
type P256EncodeNegate struct {
	runar.SmartContract
	ExpectedCompressed runar.ByteString `runar:"readonly"`
}

// CheckNegate: (x, y) -> (x, p - y). Guards canonicity AND the 64-byte width.
func (c *P256EncodeNegate) CheckNegate(p runar.P256Point, expected runar.P256Point) {
	n := runar.P256Negate(p)
	runar.Assert(n == expected)
}

// CheckEncode: Point -> 33-byte 02/03||x, parity read at a fixed offset.
func (c *P256EncodeNegate) CheckEncode(p runar.P256Point, expected runar.ByteString) {
	e := runar.P256EncodeCompressed(p)
	runar.Assert(e == expected)
}

// CheckNegateThenEncode: compressing the negation must flip the prefix only.
func (c *P256EncodeNegate) CheckNegateThenEncode(p runar.P256Point) {
	n := runar.P256Negate(p)
	e := runar.P256EncodeCompressed(n)
	runar.Assert(e == c.ExpectedCompressed)
}

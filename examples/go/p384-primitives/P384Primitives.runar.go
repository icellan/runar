//go:build ignore

// EXCLUDED FROM THE GO BUILD — a P-384 scalar does not fit the Go mock's
// `Bigint`.
//
//	cannot use k (variable of int64 type runar.Bigint) as *big.Int value in
//	argument to runar.P384Mul
//
// Identical to p256-primitives one curve up: `Verify(k runar.Bigint, …)` is
// correct Rúnar (the parser maps `Bigint` to the arbitrary-precision `bigint`,
// and a P-384 scalar is 384 bits), P384Mul correctly takes a `*big.Int`, and
// the two cannot meet while `runar.Bigint` aliases int64. See the note in
// p256-primitives for why widening the alias is not an examples-level change.

package contract

import "runar"

type P384Primitives struct {
	runar.SmartContract
	ExpectedPoint runar.P384Point `runar:"readonly"`
}

func (c *P384Primitives) Verify(k runar.Bigint, basePoint runar.P384Point) {
	result := runar.P384Mul(basePoint, k)
	runar.Assert(runar.P384OnCurve(result))
	runar.Assert(result == c.ExpectedPoint)
}

func (c *P384Primitives) VerifyAdd(a runar.P384Point, b runar.P384Point) {
	result := runar.P384Add(a, b)
	runar.Assert(runar.P384OnCurve(result))
	runar.Assert(result == c.ExpectedPoint)
}

func (c *P384Primitives) VerifyMulGen(k runar.Bigint) {
	result := runar.P384MulGen(k)
	runar.Assert(runar.P384OnCurve(result))
	runar.Assert(result == c.ExpectedPoint)
}

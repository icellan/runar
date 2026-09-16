//go:build ignore

// EXCLUDED FROM THE GO BUILD — a P-256 scalar does not fit the Go mock's
// `Bigint`.
//
//	cannot use k (variable of int64 type runar.Bigint) as *big.Int value in
//	argument to runar.P256Mul
//
// `Verify(k runar.Bigint, …)` is correct Rúnar: the parser maps `Bigint` to the
// arbitrary-precision `bigint`, and a P-256 scalar is 256 bits. packages/runar-go
// is also correct: P256Mul takes a `*big.Int` because that is the only Go type
// that can hold one. The two cannot meet while `runar.Bigint` aliases int64.
//
// Widening the mock's `Bigint` is the fix, and it is a change to every tier's
// notion of the primitive plus roughly forty call sites across examples/go —
// not something to smuggle in behind a build tag. Same root cause as
// schnorr-zkp, integer-boundary and go-dsl-bytestring-literal, and the same one
// behind the `knownDivergent` EcPointX/EcPointY entries in
// packages/runar-go/mock_script_agreement_test.go.

package contract

import "runar"

type P256Primitives struct {
	runar.SmartContract
	ExpectedPoint runar.P256Point `runar:"readonly"`
}

func (c *P256Primitives) Verify(k runar.Bigint, basePoint runar.P256Point) {
	result := runar.P256Mul(basePoint, k)
	runar.Assert(runar.P256OnCurve(result))
	runar.Assert(result == c.ExpectedPoint)
}

func (c *P256Primitives) VerifyAdd(a runar.P256Point, b runar.P256Point) {
	result := runar.P256Add(a, b)
	runar.Assert(runar.P256OnCurve(result))
	runar.Assert(result == c.ExpectedPoint)
}

func (c *P256Primitives) VerifyMulGen(k runar.Bigint) {
	result := runar.P256MulGen(k)
	runar.Assert(runar.P256OnCurve(result))
	runar.Assert(result == c.ExpectedPoint)
}

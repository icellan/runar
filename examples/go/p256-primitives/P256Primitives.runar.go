// P256Primitives exercises the NIST P-256 built-ins.
//
// The scalar `k` is typed `runar.BigintBig` and not `runar.Bigint`. Both names
// map to the single Rúnar primitive `bigint` in every .runar.go parser, so the
// emitted ANF and script are identical either way — but a P-256 scalar is
// 256 bits, and runar.P256Mul takes the *big.Int that can hold one.
// While the parameter was `Bigint` (int64) the two could not meet and this file
// carried `//go:build ignore`, which bought the Rúnar half of the check by
// giving up the Go half: nothing ran the contract.

package contract

import runar "github.com/icellan/runar/packages/runar-go"

type P256Primitives struct {
	runar.SmartContract
	ExpectedPoint runar.P256Point `runar:"readonly"`
}

func (c *P256Primitives) Verify(k runar.BigintBig, basePoint runar.P256Point) {
	result := runar.P256Mul(basePoint, k)
	runar.Assert(runar.P256OnCurve(result))
	runar.Assert(result == c.ExpectedPoint)
}

func (c *P256Primitives) VerifyAdd(a runar.P256Point, b runar.P256Point) {
	result := runar.P256Add(a, b)
	runar.Assert(runar.P256OnCurve(result))
	runar.Assert(result == c.ExpectedPoint)
}

func (c *P256Primitives) VerifyMulGen(k runar.BigintBig) {
	result := runar.P256MulGen(k)
	runar.Assert(runar.P256OnCurve(result))
	runar.Assert(result == c.ExpectedPoint)
}

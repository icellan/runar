// P384Primitives exercises the NIST P-384 built-ins.
//
// The scalar `k` is typed `runar.BigintBig` and not `runar.Bigint`. Both names
// map to the single Rúnar primitive `bigint` in every .runar.go parser, so the
// emitted ANF and script are identical either way — but a P-384 scalar is
// 384 bits, and runar.P384Mul takes the *big.Int that can hold one.
// While the parameter was `Bigint` (int64) the two could not meet and this file
// carried `//go:build ignore`, which bought the Rúnar half of the check by
// giving up the Go half: nothing ran the contract.

package contract

import runar "github.com/icellan/runar/packages/runar-go"

type P384Primitives struct {
	runar.SmartContract
	ExpectedPoint runar.P384Point `runar:"readonly"`
}

func (c *P384Primitives) Verify(k runar.BigintBig, basePoint runar.P384Point) {
	result := runar.P384Mul(basePoint, k)
	runar.Assert(runar.P384OnCurve(result))
	runar.Assert(result == c.ExpectedPoint)
}

func (c *P384Primitives) VerifyAdd(a runar.P384Point, b runar.P384Point) {
	result := runar.P384Add(a, b)
	runar.Assert(runar.P384OnCurve(result))
	runar.Assert(result == c.ExpectedPoint)
}

func (c *P384Primitives) VerifyMulGen(k runar.BigintBig) {
	result := runar.P384MulGen(k)
	runar.Assert(runar.P384OnCurve(result))
	runar.Assert(result == c.ExpectedPoint)
}

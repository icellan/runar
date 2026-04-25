//go:build ignore

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

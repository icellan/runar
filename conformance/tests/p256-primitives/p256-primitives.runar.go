//go:build ignore

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

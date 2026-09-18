package contract

import runar "github.com/icellan/runar/packages/runar-go"

type ECPrimitives struct {
	runar.SmartContract
	Pt runar.Point `runar:"readonly"`
}

func (c *ECPrimitives) CheckX(expectedX runar.BigintBig) {
	runar.Assert(runar.BigintBigEqual(runar.EcPointX(c.Pt), expectedX))
}

func (c *ECPrimitives) CheckY(expectedY runar.BigintBig) {
	runar.Assert(runar.BigintBigEqual(runar.EcPointY(c.Pt), expectedY))
}

func (c *ECPrimitives) CheckOnCurve() {
	runar.Assert(runar.EcOnCurve(c.Pt))
}

func (c *ECPrimitives) CheckNegateY(expectedNegY runar.BigintBig) {
	negated := runar.EcNegate(c.Pt)
	runar.Assert(runar.BigintBigEqual(runar.EcPointY(negated), expectedNegY))
}

func (c *ECPrimitives) CheckModReduce(value, modulus, expected runar.Bigint) {
	runar.Assert(runar.EcModReduce(value, modulus) == expected)
}

func (c *ECPrimitives) CheckAdd(other runar.Point, expectedX, expectedY runar.BigintBig) {
	result := runar.EcAdd(c.Pt, other)
	runar.Assert(runar.BigintBigEqual(runar.EcPointX(result), expectedX))
	runar.Assert(runar.BigintBigEqual(runar.EcPointY(result), expectedY))
}

func (c *ECPrimitives) CheckMul(scalar runar.Bigint, expectedX, expectedY runar.BigintBig) {
	result := runar.EcMul(c.Pt, scalar)
	runar.Assert(runar.BigintBigEqual(runar.EcPointX(result), expectedX))
	runar.Assert(runar.BigintBigEqual(runar.EcPointY(result), expectedY))
}

func (c *ECPrimitives) CheckMulGen(scalar runar.Bigint, expectedX, expectedY runar.BigintBig) {
	result := runar.EcMulGen(scalar)
	runar.Assert(runar.BigintBigEqual(runar.EcPointX(result), expectedX))
	runar.Assert(runar.BigintBigEqual(runar.EcPointY(result), expectedY))
}

func (c *ECPrimitives) CheckMakePoint(x, y, expectedX, expectedY runar.BigintBig) {
	pt := runar.EcMakePoint(x, y)
	runar.Assert(runar.BigintBigEqual(runar.EcPointX(pt), expectedX))
	runar.Assert(runar.BigintBigEqual(runar.EcPointY(pt), expectedY))
}

func (c *ECPrimitives) CheckEncodeCompressed(expected runar.ByteString) {
	compressed := runar.EcEncodeCompressed(c.Pt)
	runar.Assert(compressed == expected)
}

func (c *ECPrimitives) CheckMulIdentity() {
	result := runar.EcMul(c.Pt, 1)
	runar.Assert(runar.BigintBigEqual(runar.EcPointX(result), runar.EcPointX(c.Pt)))
	runar.Assert(runar.BigintBigEqual(runar.EcPointY(result), runar.EcPointY(c.Pt)))
}

func (c *ECPrimitives) CheckNegateRoundtrip() {
	neg1 := runar.EcNegate(c.Pt)
	neg2 := runar.EcNegate(neg1)
	runar.Assert(runar.BigintBigEqual(runar.EcPointX(neg2), runar.EcPointX(c.Pt)))
	runar.Assert(runar.BigintBigEqual(runar.EcPointY(neg2), runar.EcPointY(c.Pt)))
}

func (c *ECPrimitives) CheckAddOnCurve(other runar.Point) {
	result := runar.EcAdd(c.Pt, other)
	runar.Assert(runar.EcOnCurve(result))
}

func (c *ECPrimitives) CheckMulGenOnCurve(scalar runar.Bigint) {
	result := runar.EcMulGen(scalar)
	runar.Assert(runar.EcOnCurve(result))
}

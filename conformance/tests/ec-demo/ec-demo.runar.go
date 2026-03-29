package contract

import "runar"

type ECDemo struct {
	runar.SmartContract
	Pt runar.Point `runar:"readonly"`
}

func (c *ECDemo) CheckX(expectedX runar.Bigint) {
	runar.Assert(runar.EcPointX(c.Pt) == expectedX)
}

func (c *ECDemo) CheckY(expectedY runar.Bigint) {
	runar.Assert(runar.EcPointY(c.Pt) == expectedY)
}

func (c *ECDemo) CheckMakePoint(x, y, expectedX, expectedY runar.Bigint) {
	p := runar.EcMakePoint(x, y)
	runar.Assert(runar.EcPointX(p) == expectedX)
	runar.Assert(runar.EcPointY(p) == expectedY)
}

func (c *ECDemo) CheckOnCurve() {
	runar.Assert(runar.EcOnCurve(c.Pt))
}

func (c *ECDemo) CheckAdd(other runar.Point, expectedX, expectedY runar.Bigint) {
	result := runar.EcAdd(c.Pt, other)
	runar.Assert(runar.EcPointX(result) == expectedX)
	runar.Assert(runar.EcPointY(result) == expectedY)
}

func (c *ECDemo) CheckMul(scalar, expectedX, expectedY runar.Bigint) {
	result := runar.EcMul(c.Pt, scalar)
	runar.Assert(runar.EcPointX(result) == expectedX)
	runar.Assert(runar.EcPointY(result) == expectedY)
}

func (c *ECDemo) CheckMulGen(scalar, expectedX, expectedY runar.Bigint) {
	result := runar.EcMulGen(scalar)
	runar.Assert(runar.EcPointX(result) == expectedX)
	runar.Assert(runar.EcPointY(result) == expectedY)
}

func (c *ECDemo) CheckNegate(expectedNegY runar.Bigint) {
	neg := runar.EcNegate(c.Pt)
	runar.Assert(runar.EcPointY(neg) == expectedNegY)
}

func (c *ECDemo) CheckNegateRoundtrip() {
	neg1 := runar.EcNegate(c.Pt)
	neg2 := runar.EcNegate(neg1)
	runar.Assert(runar.EcPointX(neg2) == runar.EcPointX(c.Pt))
	runar.Assert(runar.EcPointY(neg2) == runar.EcPointY(c.Pt))
}

func (c *ECDemo) CheckModReduce(value, modulus, expected runar.Bigint) {
	runar.Assert(runar.EcModReduce(value, modulus) == expected)
}

func (c *ECDemo) CheckEncodeCompressed(expected runar.ByteString) {
	compressed := runar.EcEncodeCompressed(c.Pt)
	runar.Assert(compressed == expected)
}

func (c *ECDemo) CheckMulIdentity() {
	result := runar.EcMul(c.Pt, 1)
	runar.Assert(runar.EcPointX(result) == runar.EcPointX(c.Pt))
	runar.Assert(runar.EcPointY(result) == runar.EcPointY(c.Pt))
}

func (c *ECDemo) CheckAddOnCurve(other runar.Point) {
	result := runar.EcAdd(c.Pt, other)
	runar.Assert(runar.EcOnCurve(result))
}

func (c *ECDemo) CheckMulGenOnCurve(scalar runar.Bigint) {
	result := runar.EcMulGen(scalar)
	runar.Assert(runar.EcOnCurve(result))
}

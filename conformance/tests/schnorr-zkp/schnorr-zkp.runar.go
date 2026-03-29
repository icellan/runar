package contract

import "runar"

type SchnorrZKP struct {
	runar.SmartContract
	PubKey runar.Point `runar:"readonly"`
}

func (c *SchnorrZKP) Verify(rPoint runar.Point, s runar.Bigint) {
	runar.Assert(runar.EcOnCurve(rPoint))
	e := runar.Bin2Num(runar.Hash256(runar.Cat(rPoint, c.PubKey)))
	sG := runar.EcMulGen(s)
	eP := runar.EcMul(c.PubKey, e)
	rhs := runar.EcAdd(rPoint, eP)
	runar.Assert(runar.EcPointX(sG) == runar.EcPointX(rhs))
	runar.Assert(runar.EcPointY(sG) == runar.EcPointY(rhs))
}

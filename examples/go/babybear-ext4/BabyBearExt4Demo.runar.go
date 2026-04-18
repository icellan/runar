package contract

import runar "github.com/icellan/runar/packages/runar-go"

// BabyBearExt4Demo demonstrates Baby Bear Ext4 (quartic extension field)
// arithmetic and the core FRI colinearity folding relation used in SP1 STARK
// proofs.
type BabyBearExt4Demo struct {
	runar.SmartContract
}

// CheckMul verifies Ext4 multiplication (all 4 components).
func (bb *BabyBearExt4Demo) CheckMul(
	a0, a1, a2, a3,
	b0, b1, b2, b3,
	e0, e1, e2, e3 runar.Bigint,
) {
	runar.Assert(runar.BbExt4Mul0(a0, a1, a2, a3, b0, b1, b2, b3) == e0)
	runar.Assert(runar.BbExt4Mul1(a0, a1, a2, a3, b0, b1, b2, b3) == e1)
	runar.Assert(runar.BbExt4Mul2(a0, a1, a2, a3, b0, b1, b2, b3) == e2)
	runar.Assert(runar.BbExt4Mul3(a0, a1, a2, a3, b0, b1, b2, b3) == e3)
}

// CheckInv verifies Ext4 inverse (all 4 components).
func (bb *BabyBearExt4Demo) CheckInv(
	a0, a1, a2, a3,
	e0, e1, e2, e3 runar.Bigint,
) {
	runar.Assert(runar.BbExt4Inv0(a0, a1, a2, a3) == e0)
	runar.Assert(runar.BbExt4Inv1(a0, a1, a2, a3) == e1)
	runar.Assert(runar.BbExt4Inv2(a0, a1, a2, a3) == e2)
	runar.Assert(runar.BbExt4Inv3(a0, a1, a2, a3) == e3)
}

// CheckFriFold verifies the core FRI colinearity folding relation.
func (bb *BabyBearExt4Demo) CheckFriFold(
	x,
	fx0, fx1, fx2, fx3,
	fnx0, fnx1, fnx2, fnx3,
	a0, a1, a2, a3,
	eg0, eg1, eg2, eg3 runar.Bigint,
) {
	s0 := runar.BbFieldAdd(fx0, fnx0)
	s1 := runar.BbFieldAdd(fx1, fnx1)
	s2 := runar.BbFieldAdd(fx2, fnx2)
	s3 := runar.BbFieldAdd(fx3, fnx3)
	inv2 := runar.BbFieldInv(2)
	hs0 := runar.BbFieldMul(s0, inv2)
	hs1 := runar.BbFieldMul(s1, inv2)
	hs2 := runar.BbFieldMul(s2, inv2)
	hs3 := runar.BbFieldMul(s3, inv2)
	d0 := runar.BbFieldSub(fx0, fnx0)
	d1 := runar.BbFieldSub(fx1, fnx1)
	d2 := runar.BbFieldSub(fx2, fnx2)
	d3 := runar.BbFieldSub(fx3, fnx3)
	ad0 := runar.BbExt4Mul0(a0, a1, a2, a3, d0, d1, d2, d3)
	ad1 := runar.BbExt4Mul1(a0, a1, a2, a3, d0, d1, d2, d3)
	ad2 := runar.BbExt4Mul2(a0, a1, a2, a3, d0, d1, d2, d3)
	ad3 := runar.BbExt4Mul3(a0, a1, a2, a3, d0, d1, d2, d3)
	inv2x := runar.BbFieldInv(runar.BbFieldMul(2, x))
	at0 := runar.BbFieldMul(ad0, inv2x)
	at1 := runar.BbFieldMul(ad1, inv2x)
	at2 := runar.BbFieldMul(ad2, inv2x)
	at3 := runar.BbFieldMul(ad3, inv2x)
	g0 := runar.BbFieldAdd(hs0, at0)
	g1 := runar.BbFieldAdd(hs1, at1)
	g2 := runar.BbFieldAdd(hs2, at2)
	g3 := runar.BbFieldAdd(hs3, at3)
	runar.Assert(g0 == eg0)
	runar.Assert(g1 == eg1)
	runar.Assert(g2 == eg2)
	runar.Assert(g3 == eg3)
}

// BabyBearExt4Demo — Demonstrates Baby Bear Ext4 (quartic extension field)
// arithmetic and the core FRI colinearity folding relation used in SP1 STARK
// proofs.
module BabyBearExt4Demo {
    use runar::math::{bbFieldAdd, bbFieldSub, bbFieldMul, bbFieldInv,
        bbExt4Mul0, bbExt4Mul1, bbExt4Mul2, bbExt4Mul3,
        bbExt4Inv0, bbExt4Inv1, bbExt4Inv2, bbExt4Inv3};

    struct BabyBearExt4Demo {
    }

    // Ext4 multiplication: verify all 4 components.
    public fun check_mul(
        contract: &BabyBearExt4Demo,
        a0: bigint, a1: bigint, a2: bigint, a3: bigint,
        b0: bigint, b1: bigint, b2: bigint, b3: bigint,
        e0: bigint, e1: bigint, e2: bigint, e3: bigint
    ) {
        assert!(bbExt4Mul0(a0, a1, a2, a3, b0, b1, b2, b3) == e0, 0);
        assert!(bbExt4Mul1(a0, a1, a2, a3, b0, b1, b2, b3) == e1, 0);
        assert!(bbExt4Mul2(a0, a1, a2, a3, b0, b1, b2, b3) == e2, 0);
        assert!(bbExt4Mul3(a0, a1, a2, a3, b0, b1, b2, b3) == e3, 0);
    }

    // Ext4 inverse: verify all 4 components.
    public fun check_inv(
        contract: &BabyBearExt4Demo,
        a0: bigint, a1: bigint, a2: bigint, a3: bigint,
        e0: bigint, e1: bigint, e2: bigint, e3: bigint
    ) {
        assert!(bbExt4Inv0(a0, a1, a2, a3) == e0, 0);
        assert!(bbExt4Inv1(a0, a1, a2, a3) == e1, 0);
        assert!(bbExt4Inv2(a0, a1, a2, a3) == e2, 0);
        assert!(bbExt4Inv3(a0, a1, a2, a3) == e3, 0);
    }

    // FRI colinearity check: the core FRI folding relation.
    public fun check_fri_fold(
        contract: &BabyBearExt4Demo,
        x: bigint,
        fx0: bigint, fx1: bigint, fx2: bigint, fx3: bigint,
        fnx0: bigint, fnx1: bigint, fnx2: bigint, fnx3: bigint,
        a0: bigint, a1: bigint, a2: bigint, a3: bigint,
        eg0: bigint, eg1: bigint, eg2: bigint, eg3: bigint
    ) {
        let s0: bigint = bbFieldAdd(fx0, fnx0);
        let s1: bigint = bbFieldAdd(fx1, fnx1);
        let s2: bigint = bbFieldAdd(fx2, fnx2);
        let s3: bigint = bbFieldAdd(fx3, fnx3);
        let inv2: bigint = bbFieldInv(2);
        let hs0: bigint = bbFieldMul(s0, inv2);
        let hs1: bigint = bbFieldMul(s1, inv2);
        let hs2: bigint = bbFieldMul(s2, inv2);
        let hs3: bigint = bbFieldMul(s3, inv2);
        let d0: bigint = bbFieldSub(fx0, fnx0);
        let d1: bigint = bbFieldSub(fx1, fnx1);
        let d2: bigint = bbFieldSub(fx2, fnx2);
        let d3: bigint = bbFieldSub(fx3, fnx3);
        let ad0: bigint = bbExt4Mul0(a0, a1, a2, a3, d0, d1, d2, d3);
        let ad1: bigint = bbExt4Mul1(a0, a1, a2, a3, d0, d1, d2, d3);
        let ad2: bigint = bbExt4Mul2(a0, a1, a2, a3, d0, d1, d2, d3);
        let ad3: bigint = bbExt4Mul3(a0, a1, a2, a3, d0, d1, d2, d3);
        let inv2x: bigint = bbFieldInv(bbFieldMul(2, x));
        let at0: bigint = bbFieldMul(ad0, inv2x);
        let at1: bigint = bbFieldMul(ad1, inv2x);
        let at2: bigint = bbFieldMul(ad2, inv2x);
        let at3: bigint = bbFieldMul(ad3, inv2x);
        let g0: bigint = bbFieldAdd(hs0, at0);
        let g1: bigint = bbFieldAdd(hs1, at1);
        let g2: bigint = bbFieldAdd(hs2, at2);
        let g3: bigint = bbFieldAdd(hs3, at3);
        assert!(g0 == eg0, 0);
        assert!(g1 == eg1, 0);
        assert!(g2 == eg2, 0);
        assert!(g3 == eg3, 0);
    }
}

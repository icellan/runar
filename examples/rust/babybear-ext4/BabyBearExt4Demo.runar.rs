use runar::prelude::*;

/// BabyBearExt4Demo -- Demonstrates Baby Bear Ext4 (quartic extension field)
/// arithmetic and the core FRI colinearity folding relation used in SP1 STARK
/// proofs.
#[runar::contract]
pub struct BabyBearExt4Demo {}

#[runar::methods(BabyBearExt4Demo)]
impl BabyBearExt4Demo {
    /// Ext4 multiplication: verify all 4 components.
    #[public]
    pub fn check_mul(
        &self,
        a0: Bigint, a1: Bigint, a2: Bigint, a3: Bigint,
        b0: Bigint, b1: Bigint, b2: Bigint, b3: Bigint,
        e0: Bigint, e1: Bigint, e2: Bigint, e3: Bigint,
    ) {
        assert!(bb_ext4_mul0(a0, a1, a2, a3, b0, b1, b2, b3) == e0);
        assert!(bb_ext4_mul1(a0, a1, a2, a3, b0, b1, b2, b3) == e1);
        assert!(bb_ext4_mul2(a0, a1, a2, a3, b0, b1, b2, b3) == e2);
        assert!(bb_ext4_mul3(a0, a1, a2, a3, b0, b1, b2, b3) == e3);
    }

    /// Ext4 inverse: verify all 4 components.
    #[public]
    pub fn check_inv(
        &self,
        a0: Bigint, a1: Bigint, a2: Bigint, a3: Bigint,
        e0: Bigint, e1: Bigint, e2: Bigint, e3: Bigint,
    ) {
        assert!(bb_ext4_inv0(a0, a1, a2, a3) == e0);
        assert!(bb_ext4_inv1(a0, a1, a2, a3) == e1);
        assert!(bb_ext4_inv2(a0, a1, a2, a3) == e2);
        assert!(bb_ext4_inv3(a0, a1, a2, a3) == e3);
    }

    /// FRI colinearity check: the core FRI folding relation.
    #[public]
    pub fn check_fri_fold(
        &self,
        x: Bigint,
        fx0: Bigint, fx1: Bigint, fx2: Bigint, fx3: Bigint,
        fnx0: Bigint, fnx1: Bigint, fnx2: Bigint, fnx3: Bigint,
        a0: Bigint, a1: Bigint, a2: Bigint, a3: Bigint,
        eg0: Bigint, eg1: Bigint, eg2: Bigint, eg3: Bigint,
    ) {
        let s0 = bb_field_add(fx0, fnx0);
        let s1 = bb_field_add(fx1, fnx1);
        let s2 = bb_field_add(fx2, fnx2);
        let s3 = bb_field_add(fx3, fnx3);
        let inv2 = bb_field_inv(2);
        let hs0 = bb_field_mul(s0, inv2);
        let hs1 = bb_field_mul(s1, inv2);
        let hs2 = bb_field_mul(s2, inv2);
        let hs3 = bb_field_mul(s3, inv2);
        let d0 = bb_field_sub(fx0, fnx0);
        let d1 = bb_field_sub(fx1, fnx1);
        let d2 = bb_field_sub(fx2, fnx2);
        let d3 = bb_field_sub(fx3, fnx3);
        let ad0 = bb_ext4_mul0(a0, a1, a2, a3, d0, d1, d2, d3);
        let ad1 = bb_ext4_mul1(a0, a1, a2, a3, d0, d1, d2, d3);
        let ad2 = bb_ext4_mul2(a0, a1, a2, a3, d0, d1, d2, d3);
        let ad3 = bb_ext4_mul3(a0, a1, a2, a3, d0, d1, d2, d3);
        let inv2x = bb_field_inv(bb_field_mul(2, x));
        let at0 = bb_field_mul(ad0, inv2x);
        let at1 = bb_field_mul(ad1, inv2x);
        let at2 = bb_field_mul(ad2, inv2x);
        let at3 = bb_field_mul(ad3, inv2x);
        let g0 = bb_field_add(hs0, at0);
        let g1 = bb_field_add(hs1, at1);
        let g2 = bb_field_add(hs2, at2);
        let g3 = bb_field_add(hs3, at3);
        assert!(g0 == eg0);
        assert!(g1 == eg1);
        assert!(g2 == eg2);
        assert!(g3 == eg3);
    }
}

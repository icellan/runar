pragma runar ^0.1.0;

/// @title BabyBearExt4Demo
/// @notice Demonstrates Baby Bear Ext4 (quartic extension field) arithmetic
/// and the core FRI colinearity folding relation used in SP1 STARK proofs.
contract BabyBearExt4Demo is SmartContract {
    constructor() {
    }

    /// @notice Ext4 multiplication: verify all 4 components.
    function checkMul(
        bigint a0, bigint a1, bigint a2, bigint a3,
        bigint b0, bigint b1, bigint b2, bigint b3,
        bigint e0, bigint e1, bigint e2, bigint e3
    ) public {
        require(bbExt4Mul0(a0, a1, a2, a3, b0, b1, b2, b3) == e0);
        require(bbExt4Mul1(a0, a1, a2, a3, b0, b1, b2, b3) == e1);
        require(bbExt4Mul2(a0, a1, a2, a3, b0, b1, b2, b3) == e2);
        require(bbExt4Mul3(a0, a1, a2, a3, b0, b1, b2, b3) == e3);
    }

    /// @notice Ext4 inverse: verify all 4 components.
    function checkInv(
        bigint a0, bigint a1, bigint a2, bigint a3,
        bigint e0, bigint e1, bigint e2, bigint e3
    ) public {
        require(bbExt4Inv0(a0, a1, a2, a3) == e0);
        require(bbExt4Inv1(a0, a1, a2, a3) == e1);
        require(bbExt4Inv2(a0, a1, a2, a3) == e2);
        require(bbExt4Inv3(a0, a1, a2, a3) == e3);
    }

    /// @notice FRI colinearity check: the core FRI folding relation.
    function checkFriFold(
        bigint x,
        bigint fx0, bigint fx1, bigint fx2, bigint fx3,
        bigint fnx0, bigint fnx1, bigint fnx2, bigint fnx3,
        bigint a0, bigint a1, bigint a2, bigint a3,
        bigint eg0, bigint eg1, bigint eg2, bigint eg3
    ) public {
        bigint s0 = bbFieldAdd(fx0, fnx0);
        bigint s1 = bbFieldAdd(fx1, fnx1);
        bigint s2 = bbFieldAdd(fx2, fnx2);
        bigint s3 = bbFieldAdd(fx3, fnx3);
        bigint inv2 = bbFieldInv(2);
        bigint hs0 = bbFieldMul(s0, inv2);
        bigint hs1 = bbFieldMul(s1, inv2);
        bigint hs2 = bbFieldMul(s2, inv2);
        bigint hs3 = bbFieldMul(s3, inv2);
        bigint d0 = bbFieldSub(fx0, fnx0);
        bigint d1 = bbFieldSub(fx1, fnx1);
        bigint d2 = bbFieldSub(fx2, fnx2);
        bigint d3 = bbFieldSub(fx3, fnx3);
        bigint ad0 = bbExt4Mul0(a0, a1, a2, a3, d0, d1, d2, d3);
        bigint ad1 = bbExt4Mul1(a0, a1, a2, a3, d0, d1, d2, d3);
        bigint ad2 = bbExt4Mul2(a0, a1, a2, a3, d0, d1, d2, d3);
        bigint ad3 = bbExt4Mul3(a0, a1, a2, a3, d0, d1, d2, d3);
        bigint inv2x = bbFieldInv(bbFieldMul(2, x));
        bigint at0 = bbFieldMul(ad0, inv2x);
        bigint at1 = bbFieldMul(ad1, inv2x);
        bigint at2 = bbFieldMul(ad2, inv2x);
        bigint at3 = bbFieldMul(ad3, inv2x);
        bigint g0 = bbFieldAdd(hs0, at0);
        bigint g1 = bbFieldAdd(hs1, at1);
        bigint g2 = bbFieldAdd(hs2, at2);
        bigint g3 = bbFieldAdd(hs3, at3);
        require(g0 == eg0);
        require(g1 == eg1);
        require(g2 == eg2);
        require(g3 == eg3);
    }
}

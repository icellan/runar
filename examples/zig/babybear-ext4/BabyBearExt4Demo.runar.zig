const runar = @import("runar");

pub const BabyBearExt4Demo = struct {
    pub const Contract = runar.SmartContract;

    pub fn init() BabyBearExt4Demo {
        return .{};
    }

    pub fn checkMul(
        self: *const BabyBearExt4Demo,
        a0: i64, a1: i64, a2: i64, a3: i64,
        b0: i64, b1: i64, b2: i64, b3: i64,
        e0: i64, e1: i64, e2: i64, e3: i64,
    ) void {
        _ = self;
        runar.assert(runar.bbExt4Mul0(a0, a1, a2, a3, b0, b1, b2, b3) == e0);
        runar.assert(runar.bbExt4Mul1(a0, a1, a2, a3, b0, b1, b2, b3) == e1);
        runar.assert(runar.bbExt4Mul2(a0, a1, a2, a3, b0, b1, b2, b3) == e2);
        runar.assert(runar.bbExt4Mul3(a0, a1, a2, a3, b0, b1, b2, b3) == e3);
    }

    pub fn checkInv(
        self: *const BabyBearExt4Demo,
        a0: i64, a1: i64, a2: i64, a3: i64,
        e0: i64, e1: i64, e2: i64, e3: i64,
    ) void {
        _ = self;
        runar.assert(runar.bbExt4Inv0(a0, a1, a2, a3) == e0);
        runar.assert(runar.bbExt4Inv1(a0, a1, a2, a3) == e1);
        runar.assert(runar.bbExt4Inv2(a0, a1, a2, a3) == e2);
        runar.assert(runar.bbExt4Inv3(a0, a1, a2, a3) == e3);
    }

    pub fn checkFriFold(
        self: *const BabyBearExt4Demo,
        x: i64,
        fx0: i64, fx1: i64, fx2: i64, fx3: i64,
        fnx0: i64, fnx1: i64, fnx2: i64, fnx3: i64,
        a0: i64, a1: i64, a2: i64, a3: i64,
        eg0: i64, eg1: i64, eg2: i64, eg3: i64,
    ) void {
        _ = self;
        const s0 = runar.bbFieldAdd(fx0, fnx0);
        const s1 = runar.bbFieldAdd(fx1, fnx1);
        const s2 = runar.bbFieldAdd(fx2, fnx2);
        const s3 = runar.bbFieldAdd(fx3, fnx3);
        const inv2 = runar.bbFieldInv(2);
        const hs0 = runar.bbFieldMul(s0, inv2);
        const hs1 = runar.bbFieldMul(s1, inv2);
        const hs2 = runar.bbFieldMul(s2, inv2);
        const hs3 = runar.bbFieldMul(s3, inv2);
        const d0 = runar.bbFieldSub(fx0, fnx0);
        const d1 = runar.bbFieldSub(fx1, fnx1);
        const d2 = runar.bbFieldSub(fx2, fnx2);
        const d3 = runar.bbFieldSub(fx3, fnx3);
        const ad0 = runar.bbExt4Mul0(a0, a1, a2, a3, d0, d1, d2, d3);
        const ad1 = runar.bbExt4Mul1(a0, a1, a2, a3, d0, d1, d2, d3);
        const ad2 = runar.bbExt4Mul2(a0, a1, a2, a3, d0, d1, d2, d3);
        const ad3 = runar.bbExt4Mul3(a0, a1, a2, a3, d0, d1, d2, d3);
        const inv2x = runar.bbFieldInv(runar.bbFieldMul(2, x));
        const at0 = runar.bbFieldMul(ad0, inv2x);
        const at1 = runar.bbFieldMul(ad1, inv2x);
        const at2 = runar.bbFieldMul(ad2, inv2x);
        const at3 = runar.bbFieldMul(ad3, inv2x);
        const g0 = runar.bbFieldAdd(hs0, at0);
        const g1 = runar.bbFieldAdd(hs1, at1);
        const g2 = runar.bbFieldAdd(hs2, at2);
        const g3 = runar.bbFieldAdd(hs3, at3);
        runar.assert(g0 == eg0);
        runar.assert(g1 == eg1);
        runar.assert(g2 == eg2);
        runar.assert(g3 == eg3);
    }
};

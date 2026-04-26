const runar = @import("runar");

pub const ECDemo = struct {
    pub const Contract = runar.SmartContract;

    pt: runar.Point,

    pub fn init(pt: runar.Point) ECDemo {
        return .{ .pt = pt };
    }

    pub fn checkX(self: *const ECDemo, expectedX: i64) void {
        runar.assert(runar.ecPointX(self.pt) == expectedX);
    }

    pub fn checkY(self: *const ECDemo, expectedY: i64) void {
        runar.assert(runar.ecPointY(self.pt) == expectedY);
    }

    pub fn checkMakePoint(self: *const ECDemo, x: i64, y: i64, expectedX: i64, expectedY: i64) void {
        _ = self;
        const p = runar.ecMakePoint(x, y);
        runar.assert(runar.ecPointX(p) == expectedX);
        runar.assert(runar.ecPointY(p) == expectedY);
    }

    pub fn checkOnCurve(self: *const ECDemo) void {
        runar.assert(runar.ecOnCurve(self.pt));
    }

    pub fn checkAdd(self: *const ECDemo, other: runar.Point, expectedX: i64, expectedY: i64) void {
        const result = runar.ecAdd(self.pt, other);
        runar.assert(runar.ecPointX(result) == expectedX);
        runar.assert(runar.ecPointY(result) == expectedY);
    }

    pub fn checkMul(self: *const ECDemo, scalar: i64, expectedX: i64, expectedY: i64) void {
        const result = runar.ecMul(self.pt, scalar);
        runar.assert(runar.ecPointX(result) == expectedX);
        runar.assert(runar.ecPointY(result) == expectedY);
    }

    pub fn checkMulGen(self: *const ECDemo, scalar: i64, expectedX: i64, expectedY: i64) void {
        _ = self;
        const result = runar.ecMulGen(scalar);
        runar.assert(runar.ecPointX(result) == expectedX);
        runar.assert(runar.ecPointY(result) == expectedY);
    }

    pub fn checkNegate(self: *const ECDemo, expectedNegY: i64) void {
        const neg = runar.ecNegate(self.pt);
        runar.assert(runar.ecPointY(neg) == expectedNegY);
    }

    pub fn checkNegateRoundtrip(self: *const ECDemo) void {
        const neg1 = runar.ecNegate(self.pt);
        const neg2 = runar.ecNegate(neg1);
        runar.assert(runar.ecPointX(neg2) == runar.ecPointX(self.pt));
        runar.assert(runar.ecPointY(neg2) == runar.ecPointY(self.pt));
    }

    pub fn checkModReduce(self: *const ECDemo, value: i64, modulus: i64, expected: i64) void {
        _ = self;
        runar.assert(runar.ecModReduce(value, modulus) == expected);
    }

    pub fn checkEncodeCompressed(self: *const ECDemo, expected: runar.ByteString) void {
        const compressed = runar.ecEncodeCompressed(self.pt);
        runar.assert(runar.bytesEq(compressed, expected));
    }

    pub fn checkMulIdentity(self: *const ECDemo) void {
        const result = runar.ecMul(self.pt, 1);
        runar.assert(runar.ecPointX(result) == runar.ecPointX(self.pt));
        runar.assert(runar.ecPointY(result) == runar.ecPointY(self.pt));
    }

    pub fn checkAddOnCurve(self: *const ECDemo, other: runar.Point) void {
        const result = runar.ecAdd(self.pt, other);
        runar.assert(runar.ecOnCurve(result));
    }

    pub fn checkMulGenOnCurve(self: *const ECDemo, scalar: i64) void {
        _ = self;
        const result = runar.ecMulGen(scalar);
        runar.assert(runar.ecOnCurve(result));
    }
};

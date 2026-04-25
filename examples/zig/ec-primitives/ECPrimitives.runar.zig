const runar = @import("runar");

pub const ECPrimitives = struct {
    pub const Contract = runar.SmartContract;

    pt: runar.Point,

    pub fn init(pt: runar.Point) ECPrimitives {
        return .{ .pt = pt };
    }

    pub fn checkX(self: *const ECPrimitives, expectedX: i64) void {
        runar.assert(runar.ecPointX(self.pt) == expectedX);
    }

    pub fn checkY(self: *const ECPrimitives, expectedY: i64) void {
        runar.assert(runar.ecPointY(self.pt) == expectedY);
    }

    pub fn checkOnCurve(self: *const ECPrimitives) void {
        runar.assert(runar.ecOnCurve(self.pt));
    }

    pub fn checkNegateY(self: *const ECPrimitives, expectedNegY: i64) void {
        const negated = runar.ecNegate(self.pt);
        runar.assert(runar.ecPointY(negated) == expectedNegY);
    }

    pub fn checkModReduce(self: *const ECPrimitives, value: i64, modulus: i64, expected: i64) void {
        _ = self;
        runar.assert(runar.ecModReduce(value, modulus) == expected);
    }

    pub fn checkAdd(self: *const ECPrimitives, other: runar.Point, expectedX: i64, expectedY: i64) void {
        const result = runar.ecAdd(self.pt, other);
        runar.assert(runar.ecPointX(result) == expectedX);
        runar.assert(runar.ecPointY(result) == expectedY);
    }

    pub fn checkMul(self: *const ECPrimitives, scalar: i64, expectedX: i64, expectedY: i64) void {
        const result = runar.ecMul(self.pt, scalar);
        runar.assert(runar.ecPointX(result) == expectedX);
        runar.assert(runar.ecPointY(result) == expectedY);
    }

    pub fn checkMulGen(self: *const ECPrimitives, scalar: i64, expectedX: i64, expectedY: i64) void {
        _ = self;
        const result = runar.ecMulGen(scalar);
        runar.assert(runar.ecPointX(result) == expectedX);
        runar.assert(runar.ecPointY(result) == expectedY);
    }

    pub fn checkMakePoint(self: *const ECPrimitives, x: i64, y: i64, expectedX: i64, expectedY: i64) void {
        _ = self;
        const pt = runar.ecMakePoint(x, y);
        runar.assert(runar.ecPointX(pt) == expectedX);
        runar.assert(runar.ecPointY(pt) == expectedY);
    }

    pub fn checkEncodeCompressed(self: *const ECPrimitives, expected: runar.ByteString) void {
        const compressed = runar.ecEncodeCompressed(self.pt);
        runar.assert(compressed == expected);
    }

    pub fn checkMulIdentity(self: *const ECPrimitives) void {
        const result = runar.ecMul(self.pt, 1);
        runar.assert(runar.ecPointX(result) == runar.ecPointX(self.pt));
        runar.assert(runar.ecPointY(result) == runar.ecPointY(self.pt));
    }

    pub fn checkNegateRoundtrip(self: *const ECPrimitives) void {
        const neg1 = runar.ecNegate(self.pt);
        const neg2 = runar.ecNegate(neg1);
        runar.assert(runar.ecPointX(neg2) == runar.ecPointX(self.pt));
        runar.assert(runar.ecPointY(neg2) == runar.ecPointY(self.pt));
    }

    pub fn checkAddOnCurve(self: *const ECPrimitives, other: runar.Point) void {
        const result = runar.ecAdd(self.pt, other);
        runar.assert(runar.ecOnCurve(result));
    }

    pub fn checkMulGenOnCurve(self: *const ECPrimitives, scalar: i64) void {
        _ = self;
        const result = runar.ecMulGen(scalar);
        runar.assert(runar.ecOnCurve(result));
    }
};

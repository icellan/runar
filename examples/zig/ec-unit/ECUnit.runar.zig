const runar = @import("runar");

pub const ECUnit = struct {
    pub const Contract = runar.SmartContract;

    pubKey: runar.ByteString,

    pub fn init(pubKey: runar.ByteString) ECUnit {
        return .{ .pubKey = pubKey };
    }

    pub fn testOps(self: *const ECUnit) void {
        _ = self;
        const g = runar.ecMulGen(1);
        runar.assert(runar.ecOnCurve(g));
        const neg = runar.ecNegate(g);
        runar.assert(runar.ecOnCurve(neg));
        const doubled = runar.ecMul(g, 2);
        runar.assert(runar.ecOnCurve(doubled));
        const sum = runar.ecAdd(g, g);
        runar.assert(runar.ecOnCurve(sum));
        const x = runar.ecPointX(g);
        const y = runar.ecPointY(g);
        const rebuilt = runar.ecMakePoint(x, y);
        runar.assert(runar.ecOnCurve(rebuilt));
        const compressed = runar.ecEncodeCompressed(g);
        runar.assert(runar.len(compressed) == 33);
        runar.assert(true);
    }
};

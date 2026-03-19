const runar = @import("runar");

pub const SchnorrZKP = struct {
    pub const Contract = runar.SmartContract;

    pubKey: runar.Point,

    pub fn init(pubKey: runar.Point) SchnorrZKP {
        return .{ .pubKey = pubKey };
    }

    pub fn verify(self: *const SchnorrZKP, rPoint: runar.Point, s: runar.Bigint) void {
        runar.assert(runar.ecOnCurve(rPoint));

        const e = runar.bin2num(runar.hash256(runar.cat(rPoint, self.pubKey)));
        const sG = runar.ecMulGen(s);
        const eP = runar.ecMul(self.pubKey, e);
        const rhs = runar.ecAdd(rPoint, eP);

        runar.assert(runar.bytesEq(runar.ecEncodeCompressed(sG), runar.ecEncodeCompressed(rhs)));
    }
};

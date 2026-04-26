const runar = @import("runar");

pub const SchnorrZKP = struct {
    pub const Contract = runar.SmartContract;

    pubKey: runar.Point,

    pub fn init(pubKey: runar.Point) SchnorrZKP {
        return .{ .pubKey = pubKey };
    }

    pub fn verify(self: *const SchnorrZKP, rPoint: runar.Point, s: runar.Bigint) void {
        // Verify R is on the curve.
        runar.assert(runar.ecOnCurve(rPoint));

        // Derive challenge via Fiat-Shamir: e = bin2num(hash256(R || P)).
        const e = runar.bin2num(runar.hash256(runar.cat(rPoint, self.pubKey)));

        // Left side: s*G.
        const sG = runar.ecMulGen(s);

        // Right side: R + e*P.
        const eP = runar.ecMul(self.pubKey, e);
        const rhs = runar.ecAdd(rPoint, eP);

        // Verify equality via coordinate comparison (matches the TS canonical).
        runar.assert(runar.ecPointX(sG) == runar.ecPointX(rhs));
        runar.assert(runar.ecPointY(sG) == runar.ecPointY(rhs));
    }
};

const runar = @import("runar");

pub const SchnorrZKP = struct {
    pub const Contract = runar.SmartContract;

    pubKey: runar.Point,

    pub fn init(pubKey: runar.Point) SchnorrZKP {
        return .{ .pubKey = pubKey };
    }

    pub fn verify(self: *const SchnorrZKP, rPoint: runar.Point, s: runar.Bigint) void {
        // Bound s to the canonical range [1, n) where n is the secp256k1
        // group order (malleability gate). Inlined as a decimal literal so
        // every frontend lowers it to the same bigint_literal ANF node.
        // Value: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        runar.assert(runar.within(s, 1, 115792089237316195423570985008687907852837564279074904382605163141518161494337));

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

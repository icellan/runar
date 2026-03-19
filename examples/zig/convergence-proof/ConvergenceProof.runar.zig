const runar = @import("runar");

pub const ConvergenceProof = struct {
    pub const Contract = runar.SmartContract;

    rA: runar.Point,
    rB: runar.Point,

    pub fn init(rA: runar.Point, rB: runar.Point) ConvergenceProof {
        return .{
            .rA = rA,
            .rB = rB,
        };
    }

    pub fn proveConvergence(self: *const ConvergenceProof, deltaO: i64) void {
        runar.assert(runar.ecOnCurve(self.rA));
        runar.assert(runar.ecOnCurve(self.rB));

        const diff = runar.ecAdd(self.rA, runar.ecNegate(self.rB));
        const expected = runar.ecMulGen(deltaO);

        runar.assert(runar.bytesEq(runar.ecEncodeCompressed(diff), runar.ecEncodeCompressed(expected)));
    }
};

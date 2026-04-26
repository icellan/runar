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
        // Verify both committed points are on the curve.
        runar.assert(runar.ecOnCurve(self.rA));
        runar.assert(runar.ecOnCurve(self.rB));

        // R_A - R_B (point subtraction = addition with negated second operand).
        const diff = runar.ecAdd(self.rA, runar.ecNegate(self.rB));

        // delta_o * G (scalar multiplication of generator).
        const expected = runar.ecMulGen(deltaO);

        // Assert point equality via coordinate comparison (matches the TS canonical).
        runar.assert(runar.ecPointX(diff) == runar.ecPointX(expected));
        runar.assert(runar.ecPointY(diff) == runar.ecPointY(expected));
    }
};

// Bn254Pairing -- N-314: four-pair BN254 pairing-product check (Go-only codegen).
const runar = @import("runar");

pub const Bn254Pairing = struct {
    pub const Contract = runar.SmartContract;

    pub fn init() Bn254Pairing {
        return .{};
    }

    pub fn verify(
        self: *const Bn254Pairing,
        p1: runar.Point, q1x0: runar.Bigint, q1x1: runar.Bigint, q1y0: runar.Bigint, q1y1: runar.Bigint,
        p2: runar.Point, q2x0: runar.Bigint, q2x1: runar.Bigint, q2y0: runar.Bigint, q2y1: runar.Bigint,
        p3: runar.Point, q3x0: runar.Bigint, q3x1: runar.Bigint, q3y0: runar.Bigint, q3y1: runar.Bigint,
        p4: runar.Point, q4x0: runar.Bigint, q4x1: runar.Bigint, q4y0: runar.Bigint, q4y1: runar.Bigint,
    ) void {
        _ = self;
        runar.assert(runar.bn254MultiPairing4(
            p1, q1x0, q1x1, q1y0, q1y1,
            p2, q2x0, q2x1, q2y0, q2y1,
            p3, q3x0, q3x1, q3y0, q3y1,
            p4, q4x0, q4x1, q4y0, q4y1,
        ));
    }
};

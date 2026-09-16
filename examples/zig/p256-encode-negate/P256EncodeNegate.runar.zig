const runar = @import("runar");

// P256EncodeNegate -- Zig port. Executed coverage for p256Negate and
// p256EncodeCompressed, neither of which appeared in any fixture.
// See the `.runar.ts` port for the full rationale.
pub const P256EncodeNegate = struct {
    pub const Contract = runar.SmartContract;

    expectedCompressed: runar.ByteString,

    pub fn init(expectedCompressed: runar.ByteString) P256EncodeNegate {
        return .{ .expectedCompressed = expectedCompressed };
    }

    /// (x, y) -> (x, p - y). Guards coordinate canonicity AND the 64-byte width.
    pub fn checkNegate(self: *const P256EncodeNegate, p: runar.P256Point, expected: runar.P256Point) void {
        _ = self;
        const n = runar.p256Negate(p);
        runar.assert(n == expected);
    }

    /// Point -> 33-byte 02/03||x. Guards the width; parity read at a fixed offset.
    pub fn checkEncode(self: *const P256EncodeNegate, p: runar.P256Point, expected: runar.ByteString) void {
        _ = self;
        const e = runar.p256EncodeCompressed(p);
        runar.assert(runar.bytesEq(e, expected));
    }

    /// Composed: compressing the negation must flip the prefix and nothing else.
    pub fn checkNegateThenEncode(self: *const P256EncodeNegate, p: runar.P256Point) void {
        const n = runar.p256Negate(p);
        const e = runar.p256EncodeCompressed(n);
        runar.assert(runar.bytesEq(e, self.expectedCompressed));
    }
};

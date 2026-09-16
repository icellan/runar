const runar = @import("runar");

// P384EncodeNegate -- Zig port. Executed coverage for p384Negate and
// p384EncodeCompressed, neither of which appeared in any fixture.
// See the `.runar.ts` port for the full rationale.
pub const P384EncodeNegate = struct {
    pub const Contract = runar.SmartContract;

    expectedCompressed: runar.ByteString,

    pub fn init(expectedCompressed: runar.ByteString) P384EncodeNegate {
        return .{ .expectedCompressed = expectedCompressed };
    }

    /// (x, y) -> (x, p - y). Guards coordinate canonicity AND the 96-byte width.
    pub fn checkNegate(self: *const P384EncodeNegate, p: runar.P384Point, expected: runar.P384Point) void {
        _ = self;
        const n = runar.p384Negate(p);
        runar.assert(n == expected);
    }

    /// Point -> 49-byte 02/03||x. Guards the width; parity read at a fixed offset.
    pub fn checkEncode(self: *const P384EncodeNegate, p: runar.P384Point, expected: runar.ByteString) void {
        _ = self;
        const e = runar.p384EncodeCompressed(p);
        runar.assert(runar.bytesEq(e, expected));
    }

    /// Composed: compressing the negation must flip the prefix and nothing else.
    pub fn checkNegateThenEncode(self: *const P384EncodeNegate, p: runar.P384Point) void {
        const n = runar.p384Negate(p);
        const e = runar.p384EncodeCompressed(n);
        runar.assert(runar.bytesEq(e, self.expectedCompressed));
    }
};

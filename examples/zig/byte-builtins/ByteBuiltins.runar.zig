const runar = @import("runar");

// ByteBuiltins -- Zig port. Executed coverage for four byte-level builtins that
// no conformance fixture called: split, int2str, reverseBytes and sha256.
// See the `.runar.ts` port for the full rationale, and for why ripemd160 is
// absent.
pub const ByteBuiltins = struct {
    pub const Contract = runar.SmartContract;

    expectedDigest: runar.Sha256,

    pub fn init(expectedDigest: runar.Sha256) ByteBuiltins {
        return .{ .expectedDigest = expectedDigest };
    }

    /// OP_SPLIT. Binds the right half of `data` at `idx`.
    pub fn checkSplit(self: *const ByteBuiltins, data: runar.ByteString, idx: i64, expectedTail: runar.ByteString) void {
        const tail = runar.split(data, idx);
        runar.assert(runar.bytesEq(tail, expectedTail));
    }

    /// OP_NUM2BIN. Fixed-width little-endian sign-magnitude encoding.
    pub fn checkInt2Str(self: *const ByteBuiltins, value: i64, width: i64, expected: runar.ByteString) void {
        const s = runar.int2str(value, width);
        runar.assert(runar.bytesEq(s, expected));
    }

    /// 520 unrolled OP_SPLIT / OP_CAT iterations -- one per possible byte.
    pub fn checkReverse(self: *const ByteBuiltins, data: runar.ByteString, expected: runar.ByteString) void {
        const r = runar.reverseBytes(data);
        runar.assert(runar.bytesEq(r, expected));
    }

    /// OP_SHA256, against the digest baked into the locking script.
    pub fn checkSha256(self: *const ByteBuiltins, preimage: runar.ByteString) void {
        const h = runar.sha256(preimage);
        runar.assert(runar.bytesEq(h, self.expectedDigest));
    }
};

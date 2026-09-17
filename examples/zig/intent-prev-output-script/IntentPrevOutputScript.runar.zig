const runar = @import("runar");

// IntentPrevOutputScript exercises the extractPrevOutputScript intent
// intrinsic.
//
// It does NOT read input 0 (W6 / GhostInput). The intrinsic asserts that a
// caller-supplied byte string hashes to expectedHash and returns it; this
// contract then asserts the string is non-empty. The first argument is a
// compile-time label naming the auto-injected witness parameter
// _prevOutScript_0, which the unlocking script supplies. There is no vin
// lookup, no parent transaction and no input-count check in the emitted
// script. For a construction that binds a specific companion INPUT, see
// examples/ts/companion-verifier/.
pub const IntentPrevOutputScript = struct {
    pub const Contract = runar.StatefulSmartContract;

    expectedHash: runar.ByteString,
    count: i64 = 0,

    pub fn init(expectedHash: runar.ByteString, count: i64) IntentPrevOutputScript {
        return .{ .expectedHash = expectedHash, .count = count };
    }

    pub fn bind(self: *IntentPrevOutputScript) void {
        const s = runar.extractPrevOutputScript(0, self.expectedHash);
        runar.assert(runar.len(s) > 0);
        self.count = self.count + 1;
    }
};

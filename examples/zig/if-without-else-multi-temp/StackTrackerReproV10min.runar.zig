const runar = @import("runar");

// StackTrackerReproV10min — minimal reproducer for issue #36 in Zig form.
//
// The first `if (... < outCount)` branch leaves `scriptLen`, `blobLen`, and
// `blob` as branch-private locals on the stack. Without the lowerIf branch
// reconciliation fix, post-ENDIF cleanup misindexed against `p` and the
// downstream OP_SPLIT aborted with "first stack item must be a non-negative
// number". Mirrors the TS fixture in examples/ts/if-without-else-multi-temp/.
pub const StackTrackerReproV10min = struct {
    pub const Contract = runar.SmartContract;

    pub fn init() StackTrackerReproV10min {
        return .{};
    }

    pub fn verifyMneeTxContainsBothOutputs(
        self: *const StackTrackerReproV10min,
        rawTx: runar.ByteString,
        expectedMneeOutputBytes: runar.ByteString,
        expectedExtraDataOutputBytes: runar.ByteString,
    ) void {
        _ = self;
        var p: i64 = 46;

        const outCount: i64 = runar.bin2num(runar.cat(runar.substr(rawTx, p, 1), runar.num2bin(0, 1)));
        runar.assert(outCount < 253);
        runar.assert(outCount <= 8);
        p = p + 1;

        var foundMnee: bool = false;
        var foundExtra: bool = false;

        if (0 < outCount) {
            const scriptLen: i64 = runar.bin2num(runar.cat(runar.substr(rawTx, p + 8, 1), runar.num2bin(0, 1)));
            runar.assert(scriptLen < 253);
            const blobLen: i64 = 8 + 1 + scriptLen;
            const blob: runar.ByteString = runar.substr(rawTx, p, blobLen);
            if (runar.bytesEq(blob, expectedMneeOutputBytes)) {
                foundMnee = true;
            }
            if (runar.bytesEq(blob, expectedExtraDataOutputBytes)) {
                foundExtra = true;
            }
            p = p + blobLen;
        }
        if (1 < outCount) {
            const scriptLen: i64 = runar.bin2num(runar.cat(runar.substr(rawTx, p + 8, 1), runar.num2bin(0, 1)));
            runar.assert(scriptLen < 253);
            const blobLen: i64 = 8 + 1 + scriptLen;
            const blob: runar.ByteString = runar.substr(rawTx, p, blobLen);
            if (runar.bytesEq(blob, expectedMneeOutputBytes)) {
                foundMnee = true;
            }
            if (runar.bytesEq(blob, expectedExtraDataOutputBytes)) {
                foundExtra = true;
            }
            p = p + blobLen;
        }

        runar.assert(foundMnee);
        runar.assert(foundExtra);
    }

    pub fn other(self: *const StackTrackerReproV10min, x: runar.ByteString) void {
        _ = self;
        runar.assert(runar.bytesEq(x, x));
    }
};

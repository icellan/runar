// StackTrackerReproV10min — minimal reproducer for issue #36 in Move form.
//
// The first `if (... < outCount)` branch leaves `scriptLen`, `blobLen`, and
// `blob` as branch-private locals on the stack. Without the lowerIf branch
// reconciliation fix, post-ENDIF cleanup misindexed against `p` and the
// downstream OP_SPLIT aborted. Mirrors the TS fixture in
// examples/ts/if-without-else-multi-temp/.
module StackTrackerReproV10min {
    use runar::types::{ByteString};

    struct StackTrackerReproV10min {
    }

    public fun verifyMneeTxContainsBothOutputs(
        contract: &StackTrackerReproV10min,
        rawTx: ByteString,
        expectedMneeOutputBytes: ByteString,
        expectedExtraDataOutputBytes: ByteString
    ) {
        let mut p: bigint = 46;

        let outCount: bigint = bin2num(cat(substr(rawTx, p, 1), num2bin(0, 1)));
        assert!(outCount < 253, 0);
        assert!(outCount <= 8, 0);
        p = p + 1;

        let mut foundMnee: bool = false;
        let mut foundExtra: bool = false;

        if (0 < outCount) {
            let scriptLen: bigint = bin2num(cat(substr(rawTx, p + 8, 1), num2bin(0, 1)));
            assert!(scriptLen < 253, 0);
            let blobLen: bigint = 8 + 1 + scriptLen;
            let blob: ByteString = substr(rawTx, p, blobLen);
            if (blob == expectedMneeOutputBytes) { foundMnee = true; };
            if (blob == expectedExtraDataOutputBytes) { foundExtra = true; };
            p = p + blobLen;
        };
        if (1 < outCount) {
            let scriptLen: bigint = bin2num(cat(substr(rawTx, p + 8, 1), num2bin(0, 1)));
            assert!(scriptLen < 253, 0);
            let blobLen: bigint = 8 + 1 + scriptLen;
            let blob: ByteString = substr(rawTx, p, blobLen);
            if (blob == expectedMneeOutputBytes) { foundMnee = true; };
            if (blob == expectedExtraDataOutputBytes) { foundExtra = true; };
            p = p + blobLen;
        };

        assert!(foundMnee, 0);
        assert!(foundExtra, 0);
    }

    public fun other(contract: &StackTrackerReproV10min, x: ByteString) {
        assert!(x == x, 0);
    }
}

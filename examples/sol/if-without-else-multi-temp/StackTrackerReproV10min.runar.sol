// StackTrackerReproV10min — minimal reproducer for issue #36 in Solidity form.
//
// The first `if (... < outCount)` branch leaves `scriptLen`, `blobLen`, and
// `blob` as branch-private locals on the stack. Without the lowerIf branch
// reconciliation fix, post-ENDIF cleanup misindexed against `p` and the
// downstream OP_SPLIT aborted. Mirrors the TS fixture in
// examples/ts/if-without-else-multi-temp/.

pragma runar ^0.1.0;

contract StackTrackerReproV10min is SmartContract {
    constructor() {}

    function verifyMneeTxContainsBothOutputs(
        ByteString rawTx,
        ByteString expectedMneeOutputBytes,
        ByteString expectedExtraDataOutputBytes
    ) public {
        bigint p = 46;

        bigint outCount = bin2num(cat(substr(rawTx, p, 1), num2bin(0, 1)));
        require(outCount < 253);
        require(outCount <= 8);
        p = p + 1;

        bool foundMnee = false;
        bool foundExtra = false;

        if (0 < outCount) {
            bigint scriptLen = bin2num(cat(substr(rawTx, p + 8, 1), num2bin(0, 1)));
            require(scriptLen < 253);
            bigint blobLen = 8 + 1 + scriptLen;
            ByteString blob = substr(rawTx, p, blobLen);
            if (blob == expectedMneeOutputBytes) { foundMnee = true; }
            if (blob == expectedExtraDataOutputBytes) { foundExtra = true; }
            p = p + blobLen;
        }
        if (1 < outCount) {
            bigint scriptLen = bin2num(cat(substr(rawTx, p + 8, 1), num2bin(0, 1)));
            require(scriptLen < 253);
            bigint blobLen = 8 + 1 + scriptLen;
            ByteString blob = substr(rawTx, p, blobLen);
            if (blob == expectedMneeOutputBytes) { foundMnee = true; }
            if (blob == expectedExtraDataOutputBytes) { foundExtra = true; }
            p = p + blobLen;
        }

        require(foundMnee);
        require(foundExtra);
    }

    function other(ByteString x) public {
        require(x == x);
    }
}

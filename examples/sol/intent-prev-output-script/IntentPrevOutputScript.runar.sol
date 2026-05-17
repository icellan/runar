pragma runar ^0.1.0;

/// @title IntentPrevOutputScript
/// @notice Exercises the `extractPrevOutputScript` intent intrinsic.
/// Reads input 0's previous-output locking script via the
/// witness-bridge pattern and asserts it is non-empty after the
/// hash-equality check the intrinsic emits internally.
contract IntentPrevOutputScript is StatefulSmartContract {
    ByteString immutable expectedHash;
    bigint count;

    constructor(ByteString _expectedHash, bigint _count) {
        expectedHash = _expectedHash;
        count = _count;
    }

    function bind() public {
        ByteString s = extractPrevOutputScript(0, this.expectedHash);
        require(len(s) > 0);
        this.count = this.count + 1;
    }
}

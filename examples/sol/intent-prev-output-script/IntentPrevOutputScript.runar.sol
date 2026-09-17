pragma runar ^0.1.0;

/// @title IntentPrevOutputScript
/// @notice Exercises the `extractPrevOutputScript` intent intrinsic.
/// It does NOT read input 0 (W6 / GhostInput). The intrinsic asserts that a
/// caller-supplied byte string hashes to `expectedHash` and returns it; this
/// contract then asserts the string is non-empty. The first argument is a
/// compile-time label naming the auto-injected witness parameter
/// `_prevOutScript_0`, which the unlocking script supplies. There is no vin
/// lookup, no parent transaction and no input-count check in the emitted
/// script. For a construction that binds a specific companion INPUT, see
/// `examples/ts/companion-verifier/`.
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

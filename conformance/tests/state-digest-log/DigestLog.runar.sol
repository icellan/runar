pragma runar ^0.1.0;

/// @title DigestLog
/// @notice F-352 second witness for the mutable-state shape {Ripemd160}.
contract DigestLog is StatefulSmartContract {
    Ripemd160 digest;

    constructor(Ripemd160 _digest) {
        digest = _digest;
    }

    function replace(Ripemd160 newDigest, bigint version) public {
        require(version > 0);
        this.digest = newDigest;
    }
}

pragma runar ^0.1.0;

/// N-268: an `embedAlways` marker on a readonly field on the Solidity
/// surface. Only .runar.ts honours the directive; every other surface must
/// refuse it with the one shared "not supported by the Solidity surface
/// parser" message (mirrors N-244's sighash fix — before N-268 the Zig,
/// Ruby and Java tiers each used their own, differently worded text here).
/// With the marker replaced by prose, `metadataId` is an ordinary unreferenced
/// readonly field: every tier eliminates it by DCE, so this compiles to the
/// same P2PKH-shaped script everywhere.
contract Meta is SmartContract {
    Addr immutable pubKeyHash;
    /// @embedAlways
    ByteString immutable metadataId;

    constructor(Addr _pubKeyHash, ByteString _metadataId) {
        pubKeyHash = _pubKeyHash;
        metadataId = _metadataId;
    }

    function unlock(Sig sig, PubKey pubKey) public {
        require(hash160(pubKey) == pubKeyHash);
        require(checkSig(sig, pubKey));
    }
}

pragma runar ^0.1.0;

/// Directives — Solidity-like port of
/// `examples/ts/compiler-directives/Directives.runar.ts`.
///
/// The two compiler directives in their native Solidity-like spelling (N-093):
/// the property modifier `embedAlways` keeps `deployTag` in the locking script
/// although no method reads it, and the function modifier
/// `sighash(<FLAGS>)` declares the BIP-143 mode `spendSingle` commits to.
contract Directives is SmartContract {
    Addr immutable pubKeyHash;
    ByteString immutable embedAlways deployTag;

    constructor(Addr _pubKeyHash, ByteString _deployTag) {
        pubKeyHash = _pubKeyHash;
        deployTag = _deployTag;
    }

    function spendAll(Sig sig, PubKey pubKey) public {
        require(hash160(pubKey) == pubKeyHash);
        require(checkSig(sig, pubKey));
    }

    function spendSingle(Sig sig, PubKey pubKey) public sighash(SINGLE | FORKID) {
        require(hash160(pubKey) == pubKeyHash);
        require(checkSig(sig, pubKey));
    }
}

pragma runar ^0.1.0;

/// EmbedTags — Solidity-like port of
/// `examples/ts/compiler-directives/EmbedTags.runar.ts`.
///
/// The `embedAlways` property modifier on a fixed-array property applies to
/// every expanded slot: all three are kept although `unlock` reads only
/// `tags[1]`.
contract EmbedTags is SmartContract {
    Addr immutable pubKeyHash;
    bigint[3] immutable embedAlways tags = [7, 9, 11];

    constructor(Addr _pubKeyHash) {
        pubKeyHash = _pubKeyHash;
    }

    function unlock(Sig sig, PubKey pubKey, bigint amount) public {
        require(amount >= this.tags[1]);
        require(hash160(pubKey) == pubKeyHash);
        require(checkSig(sig, pubKey));
    }
}

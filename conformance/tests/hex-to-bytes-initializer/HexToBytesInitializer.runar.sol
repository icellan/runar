pragma runar ^0.1.0;

contract HexToBytesInitializer is SmartContract {
    ByteString immutable p2pkhPrefix = 0x1976a914;
    ByteString immutable p2pkhSuffix = 0x88ac;
    Addr immutable pubKeyHash;

    constructor(Addr _pubKeyHash) {
        pubKeyHash = _pubKeyHash;
    }

    function unlock(Sig sig, PubKey pubKey, ByteString script) public {
        require(hash160(pubKey) == pubKeyHash);
        require(cat(cat(p2pkhPrefix, pubKeyHash), p2pkhSuffix) == script);
        require(checkSig(sig, pubKey));
    }
}

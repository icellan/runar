pragma runar ^0.1.0;

contract P256Wallet is SmartContract {
    Addr immutable ecdsaPubKeyHash;
    ByteString immutable p256PubKeyHash;

    constructor(Addr _ecdsaPubKeyHash, ByteString _p256PubKeyHash) {
        ecdsaPubKeyHash = _ecdsaPubKeyHash;
        p256PubKeyHash = _p256PubKeyHash;
    }

    function spend(ByteString p256Sig, ByteString p256PubKey, Sig sig, PubKey pubKey) public {
        require(hash160(pubKey) == this.ecdsaPubKeyHash);
        require(checkSig(sig, pubKey));
        require(hash160(p256PubKey) == this.p256PubKeyHash);
        require(verifyECDSA_P256(sig, p256Sig, p256PubKey));
    }
}

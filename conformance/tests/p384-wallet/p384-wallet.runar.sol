pragma runar ^0.1.0;

contract P384Wallet is SmartContract {
    Addr immutable ecdsaPubKeyHash;
    ByteString immutable p384PubKeyHash;

    constructor(Addr _ecdsaPubKeyHash, ByteString _p384PubKeyHash) {
        ecdsaPubKeyHash = _ecdsaPubKeyHash;
        p384PubKeyHash = _p384PubKeyHash;
    }

    function spend(ByteString p384Sig, ByteString p384PubKey, Sig sig, PubKey pubKey) public {
        require(hash160(pubKey) == this.ecdsaPubKeyHash);
        require(checkSig(sig, pubKey));
        require(hash160(p384PubKey) == this.p384PubKeyHash);
        require(verifyECDSA_P384(sig, p384Sig, p384PubKey));
    }
}

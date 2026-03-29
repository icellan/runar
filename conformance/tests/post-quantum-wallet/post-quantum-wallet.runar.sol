pragma runar ^0.1.0;

contract PostQuantumWallet is SmartContract {
    Addr immutable ecdsaPubKeyHash;
    ByteString immutable wotsPubKeyHash;

    constructor(Addr _ecdsaPubKeyHash, ByteString _wotsPubKeyHash) {
        ecdsaPubKeyHash = _ecdsaPubKeyHash;
        wotsPubKeyHash = _wotsPubKeyHash;
    }

    function spend(ByteString wotsSig, ByteString wotsPubKey, Sig sig, PubKey pubKey) public {
        // Step 1: Verify ECDSA
        require(hash160(pubKey) == this.ecdsaPubKeyHash);
        require(checkSig(sig, pubKey));

        // Step 2: Verify WOTS+
        require(hash160(wotsPubKey) == this.wotsPubKeyHash);
        require(verifyWOTS(sig, wotsSig, wotsPubKey));
    }
}

pragma runar ^0.1.0;

contract SPHINCSWallet is SmartContract {
    Addr immutable ecdsaPubKeyHash;
    bytes immutable slhdsaPubKeyHash;

    constructor(Addr _ecdsaPubKeyHash, bytes _slhdsaPubKeyHash) {
        ecdsaPubKeyHash = _ecdsaPubKeyHash;
        slhdsaPubKeyHash = _slhdsaPubKeyHash;
    }

    function spend(bytes slhdsaSig, bytes slhdsaPubKey, Sig sig, PubKey pubKey) public {
        require(hash160(pubKey) == ecdsaPubKeyHash);
        require(checkSig(sig, pubKey));

        require(hash160(slhdsaPubKey) == slhdsaPubKeyHash);
        require(verifySLHDSA_SHA2_128s(sig, slhdsaSig, slhdsaPubKey));
    }
}

pragma runar ^0.1.0;

/// Hardware-backed P-256 primary spending with independent K1 recovery.
contract R1K1Wallet is SmartContract {
    Addr immutable r1SaltedPubKeyHash;
    Addr immutable k1PubKeyHash;

    constructor(Addr _r1SaltedPubKeyHash, Addr _k1PubKeyHash) {
        r1SaltedPubKeyHash = _r1SaltedPubKeyHash;
        k1PubKeyHash = _k1PubKeyHash;
    }

    function spendR1(bytes r1Sig, bytes r1PubKey, bytes r1Salt, SigHashPreimage txPreimage) public {
        require(len(r1Salt) == 32);
        require(hash160(cat(r1PubKey, r1Salt)) == r1SaltedPubKeyHash);
        require(substr(txPreimage, len(txPreimage) - 4, 4) == 0x41000000);
        require(checkPreimage(txPreimage));
        require(verifyECDSA_P256(sha256(txPreimage), r1Sig, r1PubKey));
    }

    function recoverK1(Sig k1Sig, PubKey k1PubKey) public {
        require(hash160(k1PubKey) == k1PubKeyHash);
        require(checkSig(k1Sig, k1PubKey));
    }
}

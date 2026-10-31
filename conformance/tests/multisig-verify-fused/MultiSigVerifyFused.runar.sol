pragma runar ^0.1.0;

contract MultiSigVerifyFused is SmartContract {
    PubKey immutable pk1;
    PubKey immutable pk2;
    PubKey immutable pk3;

    constructor(PubKey _pk1, PubKey _pk2, PubKey _pk3) {
        pk1 = _pk1;
        pk2 = _pk2;
        pk3 = _pk3;
    }

    function unlock(Sig sig1, Sig sig2, int amount) public {
        require(checkMultiSig([sig1, sig2], [this.pk1, this.pk2, this.pk3]));
        require(amount > 0);
    }
}

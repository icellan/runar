module MultiSigVerifyFused {
    use runar::types::{PubKey, Sig, Int};
    use runar::crypto::{checkMultiSig};

    struct MultiSigVerifyFused {
        pk1: PubKey,
        pk2: PubKey,
        pk3: PubKey,
    }

    public fun unlock(contract: &MultiSigVerifyFused, sig1: Sig, sig2: Sig, amount: Int) {
        assert!(checkMultiSig([sig1, sig2], [contract.pk1, contract.pk2, contract.pk3]), 0);
        assert!(amount > 0, 0);
    }
}

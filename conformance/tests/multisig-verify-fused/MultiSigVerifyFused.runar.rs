use runar::prelude::*;

#[runar::contract]
struct MultiSigVerifyFused {
    #[readonly]
    pk1: PubKey,
    #[readonly]
    pk2: PubKey,
    #[readonly]
    pk3: PubKey,
}

impl MultiSigVerifyFused {
    pub fn unlock(&self, sig1: &Sig, sig2: &Sig, amount: Bigint) {
        assert!(check_multi_sig([sig1, sig2], [&self.pk1, &self.pk2, &self.pk3]));
        assert!(amount > 0);
    }
}

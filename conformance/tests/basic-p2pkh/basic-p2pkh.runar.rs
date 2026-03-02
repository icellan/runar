use runar::prelude::*;

#[runar::contract]
struct P2PKH {
    #[readonly]
    pub_key_hash: Addr,
}

#[runar::methods(P2PKH)]
impl P2PKH {
    #[public]
    fn unlock(&self, sig: Sig, pub_key: PubKey) {
        assert!(hash160(pub_key) == self.pub_key_hash);
        assert!(check_sig(sig, pub_key));
    }
}

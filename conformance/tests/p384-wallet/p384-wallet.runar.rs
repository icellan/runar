use runar::prelude::*;

#[runar::contract]
struct P384Wallet {
    #[readonly]
    ecdsa_pub_key_hash: Addr,
    #[readonly]
    p384_pub_key_hash: ByteString,
}

#[runar::methods(P384Wallet)]
impl P384Wallet {
    #[public]
    fn spend(&self, p384_sig: &ByteString, p384_pub_key: &ByteString, sig: &Sig, pub_key: &PubKey) {
        assert!(hash160(pub_key) == self.ecdsa_pub_key_hash);
        assert!(check_sig(sig, pub_key));
        assert!(hash160(p384_pub_key) == self.p384_pub_key_hash);
        assert!(verify_ecdsa_p384(sig, p384_sig, p384_pub_key));
    }
}

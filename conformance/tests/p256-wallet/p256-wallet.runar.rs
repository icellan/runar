use runar::prelude::*;

#[runar::contract]
struct P256Wallet {
    #[readonly]
    ecdsa_pub_key_hash: Addr,
    #[readonly]
    p256_pub_key_hash: ByteString,
}

#[runar::methods(P256Wallet)]
impl P256Wallet {
    #[public]
    fn spend(&self, p256_sig: &ByteString, p256_pub_key: &ByteString, sig: &Sig, pub_key: &PubKey) {
        assert!(hash160(pub_key) == self.ecdsa_pub_key_hash);
        assert!(check_sig(sig, pub_key));
        assert!(hash160(p256_pub_key) == self.p256_pub_key_hash);
        assert!(verify_ecdsa_p256(sig, p256_sig, p256_pub_key));
    }
}

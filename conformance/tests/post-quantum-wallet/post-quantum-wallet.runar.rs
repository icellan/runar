use runar::prelude::*;

#[runar::contract]
struct PostQuantumWallet {
    #[readonly]
    ecdsa_pub_key_hash: Addr,
    #[readonly]
    wots_pub_key_hash: ByteString,
}

#[runar::methods(PostQuantumWallet)]
impl PostQuantumWallet {
    #[public]
    fn spend(&self, wots_sig: &ByteString, wots_pub_key: &ByteString, sig: &Sig, pub_key: &PubKey) {
        // Step 1: Verify ECDSA
        assert!(hash160(pub_key) == self.ecdsa_pub_key_hash);
        assert!(check_sig(sig, pub_key));

        // Step 2: Verify WOTS+
        assert!(hash160(wots_pub_key) == self.wots_pub_key_hash);
        assert!(verify_wots(sig, wots_sig, wots_pub_key));
    }
}

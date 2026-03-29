use runar::prelude::*;

#[runar::contract]
pub struct SPHINCSWallet {
    #[readonly]
    pub ecdsa_pub_key_hash: Addr,
    #[readonly]
    pub slhdsa_pub_key_hash: ByteString,
}

#[runar::methods(SPHINCSWallet)]
impl SPHINCSWallet {
    #[public]
    pub fn spend(&self, slhdsa_sig: ByteString, slhdsa_pub_key: ByteString, sig: Sig, pub_key: PubKey) {
        assert!(hash160(pub_key) == self.ecdsa_pub_key_hash);
        assert!(check_sig(sig, pub_key));

        assert!(hash160(slhdsa_pub_key) == self.slhdsa_pub_key_hash);
        assert!(verify_slh_dsa_sha2_128s(sig, slhdsa_sig, slhdsa_pub_key));
    }
}

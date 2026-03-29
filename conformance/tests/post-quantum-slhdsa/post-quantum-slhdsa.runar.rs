use runar::prelude::*;

#[runar::contract]
struct PostQuantumSLHDSA {
    #[readonly]
    pubkey: ByteString,
}

#[runar::methods(PostQuantumSLHDSA)]
impl PostQuantumSLHDSA {
    #[public]
    fn spend(&self, msg: &ByteString, sig: &ByteString) {
        assert!(verify_slh_dsa_sha2_128s(msg, sig, &self.pubkey));
    }
}

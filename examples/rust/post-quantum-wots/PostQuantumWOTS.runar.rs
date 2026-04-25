use runar::prelude::*;

#[runar::contract]
struct PostQuantumWOTS {
    #[readonly]
    pubkey: ByteString,
}

#[runar::methods(PostQuantumWOTS)]
impl PostQuantumWOTS {
    #[public]
    fn spend(&self, msg: &ByteString, sig: &ByteString) {
        assert!(verify_wots(msg, sig, &self.pubkey));
    }
}

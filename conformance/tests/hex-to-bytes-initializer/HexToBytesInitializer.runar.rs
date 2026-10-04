use runar::prelude::*;

#[runar::contract]
pub struct HexToBytesInitializer {
    #[readonly]
    pub p2pkh_prefix: ByteString,
    #[readonly]
    pub p2pkh_suffix: ByteString,
    #[readonly]
    pub pub_key_hash: Addr,
}

impl HexToBytesInitializer {
    pub fn init(&mut self) {
        self.p2pkh_prefix = to_byte_string("1976a914");
        self.p2pkh_suffix = to_byte_string("88ac");
    }

    pub fn unlock(&self, sig: &Sig, pub_key: &PubKey, script: &ByteString) {
        assert!(hash160(pub_key) == self.pub_key_hash);
        assert!(cat(&cat(&self.p2pkh_prefix, &self.pub_key_hash), &self.p2pkh_suffix) == script);
        assert!(check_sig(sig, pub_key));
    }
}

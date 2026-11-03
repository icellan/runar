module HexToBytesInitializer {
    use runar::types::{Addr, ByteString, PubKey, Sig};
    use runar::crypto::{hash160, check_sig};

    struct HexToBytesInitializer {
        p2pkh_prefix: ByteString = 0x1976a914,
        p2pkh_suffix: ByteString = 0x88ac,
        pub_key_hash: Addr,
    }

    public fun unlock(contract: &HexToBytesInitializer, sig: Sig, pub_key: PubKey, script: ByteString) {
        assert!(hash160(pub_key) == contract.pub_key_hash, 0);
        assert!(cat(cat(contract.p2pkh_prefix, contract.pub_key_hash), contract.p2pkh_suffix) == script, 0);
        assert!(check_sig(sig, pub_key), 0);
    }
}

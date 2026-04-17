module P384Wallet {
    use runar::types::{Addr, Sig, PubKey, ByteString};
    use runar::crypto::{hash160, check_sig, verifyECDSA_P384};

    struct P384Wallet {
        ecdsa_pub_key_hash: Addr,
        p384_pub_key_hash: ByteString,
    }

    public fun spend(contract: &P384Wallet, p384_sig: ByteString, p384_pub_key: ByteString, sig: Sig, pub_key: PubKey) {
        assert!(hash160(pub_key) == contract.ecdsa_pub_key_hash, 0);
        assert!(check_sig(sig, pub_key), 0);
        assert!(hash160(p384_pub_key) == contract.p384_pub_key_hash, 0);
        assert!(verifyECDSA_P384(sig, p384_sig, p384_pub_key), 0);
    }
}

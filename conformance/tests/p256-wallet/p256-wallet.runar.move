module P256Wallet {
    use runar::types::{Addr, Sig, PubKey, ByteString};
    use runar::crypto::{hash160, check_sig, verifyECDSA_P256};

    struct P256Wallet {
        ecdsa_pub_key_hash: Addr,
        p256_pub_key_hash: ByteString,
    }

    public fun spend(contract: &P256Wallet, p256_sig: ByteString, p256_pub_key: ByteString, sig: Sig, pub_key: PubKey) {
        assert!(hash160(pub_key) == contract.ecdsa_pub_key_hash, 0);
        assert!(check_sig(sig, pub_key), 0);
        assert!(hash160(p256_pub_key) == contract.p256_pub_key_hash, 0);
        assert!(verifyECDSA_P256(sig, p256_sig, p256_pub_key), 0);
    }
}

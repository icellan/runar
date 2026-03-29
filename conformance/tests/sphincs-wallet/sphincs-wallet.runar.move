module SPHINCSWallet {
    use runar::types::{Addr, Sig, PubKey};
    use runar::crypto::{hash160, check_sig, verify_slh_dsa_sha2_128s};

    resource struct SPHINCSWallet {
        ecdsa_pub_key_hash: Addr,
        slhdsa_pub_key_hash: ByteString,
    }

    public fun spend(contract: &SPHINCSWallet, slhdsa_sig: ByteString, slhdsa_pub_key: ByteString, sig: Sig, pub_key: PubKey) {
        assert!(hash160(pub_key) == contract.ecdsa_pub_key_hash, 0);
        assert!(check_sig(sig, pub_key), 0);

        assert!(hash160(slhdsa_pub_key) == contract.slhdsa_pub_key_hash, 0);
        assert!(verify_slh_dsa_sha2_128s(sig, slhdsa_sig, slhdsa_pub_key), 0);
    }
}

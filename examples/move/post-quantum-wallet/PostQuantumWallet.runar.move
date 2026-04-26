module PostQuantumWallet {
    use runar::types::{Addr, Sig, PubKey, ByteString};
    use runar::crypto::{hash160, check_sig, verifyWOTS};

    struct PostQuantumWallet {
        ecdsa_pub_key_hash: Addr,
        wots_pub_key_hash: ByteString,
    }

    public fun spend(contract: &PostQuantumWallet, wots_sig: ByteString, wots_pub_key: ByteString, sig: Sig, pub_key: PubKey) {
        // Step 1: Verify ECDSA
        assert!(hash160(pub_key) == contract.ecdsa_pub_key_hash, 0);
        assert!(check_sig(sig, pub_key), 0);

        // Step 2: Verify WOTS+
        assert!(hash160(wots_pub_key) == contract.wots_pub_key_hash, 0);
        assert!(verifyWOTS(sig, wots_sig, wots_pub_key), 0);
    }
}

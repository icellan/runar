module R1K1Wallet {
    use runar::types::{Addr, ByteString, PubKey, Sig, SigHashPreimage};
    use runar::crypto::{cat, check_preimage, check_sig, hash160, len, sha256, substr, verifyECDSA_P256};

    struct R1K1Wallet {
        r1_salted_pub_key_hash: Addr,
        k1_pub_key_hash: Addr,
    }

    public fun spend_r1(
        contract: &R1K1Wallet,
        r1_sig: ByteString,
        r1_pub_key: ByteString,
        r1_salt: ByteString,
        tx_preimage: SigHashPreimage,
    ) {
        assert!(len(r1_salt) == 32, 0);
        assert!(hash160(cat(r1_pub_key, r1_salt)) == contract.r1_salted_pub_key_hash, 0);
        assert!(substr(tx_preimage, len(tx_preimage) - 4, 4) == 0x41000000, 0);
        assert!(check_preimage(tx_preimage), 0);
        assert!(verifyECDSA_P256(sha256(tx_preimage), r1_sig, r1_pub_key), 0);
    }

    public fun recover_k1(contract: &R1K1Wallet, k1_sig: Sig, k1_pub_key: PubKey) {
        assert!(hash160(k1_pub_key) == contract.k1_pub_key_hash, 0);
        assert!(check_sig(k1_sig, k1_pub_key), 0);
    }
}

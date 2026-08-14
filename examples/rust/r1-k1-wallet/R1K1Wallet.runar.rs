use runar::prelude::*;

/// Hardware-backed P-256 primary spending with independent K1 recovery.
#[runar::contract]
pub struct R1K1Wallet {
    #[readonly]
    pub r1_salted_pub_key_hash: Addr,
    #[readonly]
    pub k1_pub_key_hash: Addr,
}

impl R1K1Wallet {
    pub fn spend_r1(
        &self,
        r1_sig: &ByteString,
        r1_pub_key: &ByteString,
        r1_salt: &ByteString,
        tx_preimage: &SigHashPreimage,
    ) {
        assert!(len(r1_salt) == 32);
        assert!(hash160(&cat(r1_pub_key, r1_salt)) == self.r1_salted_pub_key_hash);
        assert!(substr(tx_preimage, len(tx_preimage) - 4, 4) == "41000000");
        assert!(check_preimage(tx_preimage));
        assert!(verify_ecdsa_p256(&sha256(tx_preimage), r1_sig, r1_pub_key));
    }

    pub fn recover_k1(&self, k1_sig: &Sig, k1_pub_key: &PubKey) {
        assert!(hash160(k1_pub_key) == self.k1_pub_key_hash);
        assert!(check_sig(k1_sig, k1_pub_key));
    }
}

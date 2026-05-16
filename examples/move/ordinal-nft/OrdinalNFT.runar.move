// OrdinalNFT -- Pay-to-Public-Key-Hash lock for a 1sat ordinal inscription.
//
// A stateless P2PKH contract used to lock an ordinal NFT. The owner (holder of
// the private key whose public key hashes to `pub_key_hash`) can unlock and
// transfer the ordinal by providing a valid signature and public key.
//
// Ordinal Inscriptions:
//   A 1sat ordinal NFT is a UTXO carrying exactly 1 satoshi with an inscription
//   envelope embedded in the locking script. The inscription is a no-op
//   (OP_FALSE OP_IF ... OP_ENDIF) that doesn't affect script execution but
//   permanently records content (image, text, JSON, etc.) on-chain.
//
//   The inscription envelope is injected by the SDK's `withInscription()`
//   method at deployment time -- the contract logic itself is just standard P2PKH.
//
// Script Layout:
//   Unlocking: <sig> <pubKey>
//   Locking:   OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG [inscription envelope]
module OrdinalNFT {
    use runar::types::{Addr, PubKey, Sig};
    use runar::crypto::{hash160, check_sig};

    struct OrdinalNFT {
        pub_key_hash: Addr,
    }

    // Unlock by proving ownership of the private key corresponding to pub_key_hash.
    public fun unlock(contract: &OrdinalNFT, sig: Sig, pub_key: PubKey) {
        assert!(hash160(pub_key) == contract.pub_key_hash, 0);
        assert!(check_sig(sig, pub_key), 0);
    }
}

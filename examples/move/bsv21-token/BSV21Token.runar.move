// BSV21Token -- Pay-to-Public-Key-Hash lock for a BSV-21 fungible token.
//
// BSV-21 (v2) is an improvement over BSV-20 that uses ID-based tokens instead
// of tick-based. The token ID is derived from the deploy transaction
// (`<txid>_<vout>`), eliminating ticker squatting and enabling admin-controlled
// distribution.
//
// BSV-21 Token Lifecycle:
//   1. Deploy+Mint -- A single inscription deploys the token and mints the
//                     initial supply atomically. The token ID is the outpoint
//                     of the output containing this inscription.
//   2. Transfer    -- Inscribe a transfer JSON referencing the token ID and
//                     amount.
//
// The SDK helpers `BSV21.deployMint()` and `BSV21.transfer()` build the correct
// inscription payloads for each operation.
module BSV21Token {
    use runar::types::{Addr, PubKey, Sig};
    use runar::crypto::{hash160, check_sig};

    struct BSV21Token {
        pub_key_hash: Addr,
    }

    // Unlock by proving ownership of the private key corresponding to pub_key_hash.
    public fun unlock(contract: &BSV21Token, sig: Sig, pub_key: PubKey) {
        assert!(hash160(pub_key) == contract.pub_key_hash, 0);
        assert!(check_sig(sig, pub_key), 0);
    }
}

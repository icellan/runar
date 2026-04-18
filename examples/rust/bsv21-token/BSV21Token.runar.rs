use runar::prelude::*;

/// BSV21Token — Pay-to-Public-Key-Hash lock for a BSV-21 fungible token.
///
/// BSV-21 (v2) is an improvement over BSV-20 that uses ID-based tokens instead
/// of tick-based. The token ID is derived from the deploy transaction
/// (`<txid>_<vout>`), eliminating ticker squatting and enabling admin-controlled
/// distribution.
///
/// ## BSV-21 Token Lifecycle
///
/// 1. **Deploy+Mint** — A single inscription deploys the token and mints the
///    initial supply in one atomic operation. The token ID is the outpoint of
///    the output containing this inscription.
/// 2. **Transfer** — Inscribe a transfer JSON referencing the token ID and
///    amount.
///
/// The SDK helpers `bsv21_deploy_mint` and `bsv21_transfer` in
/// `runar::sdk::ordinals` build the correct inscription payloads for each
/// operation.
#[runar::contract]
pub struct BSV21Token {
    #[readonly]
    pub pub_key_hash: Addr,
}

#[runar::methods(BSV21Token)]
impl BSV21Token {
    /// Unlock by proving ownership of the private key corresponding to
    /// `pub_key_hash`.
    #[public]
    pub fn unlock(&self, sig: &Sig, pub_key: &PubKey) {
        assert!(hash160(pub_key) == self.pub_key_hash);
        assert!(check_sig(sig, pub_key));
    }
}

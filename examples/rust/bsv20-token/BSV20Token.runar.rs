use runar::prelude::*;

/// BSV20Token — Pay-to-Public-Key-Hash lock for a BSV-20 fungible token.
///
/// BSV-20 is a 1sat ordinals token standard where fungible tokens are represented
/// as inscriptions on P2PKH UTXOs. The contract logic is standard P2PKH — the
/// token semantics (deploy, mint, transfer) are encoded in the inscription
/// envelope and interpreted by indexers, not by the script itself.
///
/// ## BSV-20 Token Lifecycle
///
/// 1. **Deploy** — Inscribe a deploy JSON
///    (`{"p":"bsv-20","op":"deploy","tick":"RUNAR","max":"21000000"}`)
///    onto a UTXO to register a new ticker. First deployer wins.
/// 2. **Mint** — Inscribe a mint JSON
///    (`{"p":"bsv-20","op":"mint","tick":"RUNAR","amt":"1000"}`) to claim
///    tokens up to the per-mint limit.
/// 3. **Transfer** — Inscribe a transfer JSON
///    (`{"p":"bsv-20","op":"transfer","tick":"RUNAR","amt":"50"}`) to move
///    tokens between addresses.
///
/// The SDK helpers `bsv20_deploy`, `bsv20_mint`, and `bsv20_transfer` in
/// `runar::sdk::ordinals` build the correct inscription payloads for each
/// operation.
#[runar::contract]
pub struct BSV20Token {
    #[readonly]
    pub pub_key_hash: Addr,
}

#[runar::methods(BSV20Token)]
impl BSV20Token {
    /// Unlock by proving ownership of the private key corresponding to
    /// `pub_key_hash`.
    #[public]
    pub fn unlock(&self, sig: &Sig, pub_key: &PubKey) {
        assert!(hash160(pub_key) == self.pub_key_hash);
        assert!(check_sig(sig, pub_key));
    }
}

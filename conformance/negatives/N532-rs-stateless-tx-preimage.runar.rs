// D10 — a STATELESS Rust-DSL contract declares a tx_preimage field. In the
// Rust DSL that field is the implicit preimage of a stateful contract, which
// the compiler checks at every public method's entry; a stateless contract
// never checks it, so every extractor read of it is unverified (and the tiers
// used to split: two compiled it as stateful, one as an unspendable script,
// four refused it with unrelated errors). Every tier refuses it in the parser:
//   a stateless contract cannot declare tx_preimage: nothing checks it against the spending transaction, so every field read from it is unverified; use #[runar::stateful_contract], or take the preimage as a method parameter and assert!(check_preimage(&preimage))
use runar::prelude::*;

#[runar::contract]
pub struct N532 {
    pub tx_preimage: SigHashPreimage,
}

impl N532 {
    pub fn spend(&self, x: Bigint) {
        assert!(extract_amount(&self.tx_preimage) >= x);
    }
}

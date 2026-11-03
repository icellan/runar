use runar::prelude::*;

/// Directives -- Rust DSL port of
/// `examples/ts/compiler-directives/Directives.runar.ts`.
///
/// The two compiler directives in their native Rust spelling (N-093): the field
/// attribute `embed_always` keeps `deploy_tag` in the locking script although
/// no method reads it, and the method attribute `sighash(<FLAGS>)`
/// declares the BIP-143 mode `spend_single` commits to. `#[runar::contract]`
/// strips the field attribute and `sighash` is a pass-through attribute macro
/// from the prelude, so the contract also compiles as ordinary Rust.
#[runar::contract]
pub struct Directives {
    #[readonly]
    pub pub_key_hash: Addr,
    #[readonly]
    #[embed_always]
    pub deploy_tag: ByteString,
}

impl Directives {
    pub fn spend_all(&self, sig: &Sig, pub_key: &PubKey) {
        assert!(hash160(pub_key) == self.pub_key_hash);
        assert!(check_sig(sig, pub_key));
    }

    #[sighash(SINGLE | FORKID)]
    pub fn spend_single(&self, sig: &Sig, pub_key: &PubKey) {
        assert!(hash160(pub_key) == self.pub_key_hash);
        assert!(check_sig(sig, pub_key));
    }
}

// N-268: an `embedAlways` marker on a readonly field on the Rust surface.
// Only .runar.ts honours the directive; every other surface must refuse it
// with the one shared "not supported by the Rust surface parser" message
// (mirrors N-244's sighash fix — before N-268 the Zig, Ruby and Java tiers
// each used their own, differently worded text here).
// With the marker replaced by prose, pub_metadata_id is an ordinary
// unreferenced readonly field: every tier eliminates it by DCE, so this
// compiles to the same P2PKH-shaped script everywhere.
use runar::prelude::*;

#[runar::contract]
pub struct Meta {
    #[readonly]
    pub pub_key_hash: Addr,
    // @embedAlways
    #[readonly]
    pub metadata_id: ByteString,
}

impl Meta {
    pub fn unlock(&self, sig: &Sig, pub_key: &PubKey) {
        assert!(hash160(pub_key) == self.pub_key_hash);
        assert!(check_sig(sig, pub_key));
    }
}

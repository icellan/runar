use runar::prelude::*;

/// EmbedTags -- Rust DSL port of
/// `examples/ts/compiler-directives/EmbedTags.runar.ts`.
///
/// The `embed_always` attribute on a fixed-array field applies to every expanded slot: all
/// three are kept although `unlock` reads only `tags[1]`. The array literal
/// lives in the private `init()` method, which is how the Rust DSL spells a
/// property initializer.
#[runar::contract]
pub struct EmbedTags {
    #[readonly]
    pub pub_key_hash: Addr,
    #[readonly]
    #[embed_always]
    pub tags: [Bigint; 3],
}

impl EmbedTags {
    pub fn init(&mut self) {
        self.tags = [7, 9, 11];
    }

    pub fn unlock(&self, sig: &Sig, pub_key: &PubKey, amount: Bigint) {
        assert!(amount >= self.tags[1]);
        assert!(hash160(pub_key) == self.pub_key_hash);
        assert!(check_sig(sig, pub_key));
    }
}

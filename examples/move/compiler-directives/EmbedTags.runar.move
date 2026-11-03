// EmbedTags — Move-style port of
// `examples/ts/compiler-directives/EmbedTags.runar.ts`.
//
// The embed_always attribute on a FixedArray field applies to every expanded slot: all
// three are kept although `unlock` reads only `tags[1]`.
module EmbedTags {
    use runar::types::{Addr, PubKey, Sig};
    use runar::crypto::{hash160, check_sig};

    struct EmbedTags {
        pub_key_hash: Addr,
        #[embed_always]
        tags: FixedArray<bigint, 3> = [7, 9, 11],
    }

    public fun unlock(contract: &EmbedTags, sig: Sig, pub_key: PubKey, amount: bigint) {
        assert!(amount >= contract.tags[1], 0);
        assert!(hash160(pub_key) == contract.pub_key_hash, 0);
        assert!(check_sig(sig, pub_key), 0);
    }
}

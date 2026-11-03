// N-268: an `embedAlways` marker on a readonly field on the Move surface.
// Only .runar.ts honours the directive; every other surface must refuse it
// with the one shared "not supported by the Move surface parser" message
// (mirrors N-244's sighash fix — before N-268 the Zig, Ruby and Java tiers
// each used their own, differently worded text here).
// With the marker replaced by prose, `metadata_id` is an ordinary
// unreferenced readonly field: every tier eliminates it by DCE, so this
// compiles to the same P2PKH-shaped script everywhere.
module Meta {
    use runar::types::{Addr, PubKey, Sig, ByteString};
    use runar::crypto::{hash160, check_sig};

    struct Meta {
        pub_key_hash: Addr,
        // @embedAlways
        metadata_id: ByteString,
    }

    public fun unlock(contract: &Meta, sig: Sig, pub_key: PubKey) {
        assert!(hash160(pub_key) == contract.pub_key_hash, 0);
        assert!(check_sig(sig, pub_key), 0);
    }
}

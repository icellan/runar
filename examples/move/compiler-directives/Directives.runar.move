// Directives — Move-style port of
// `examples/ts/compiler-directives/Directives.runar.ts`.
//
// The two compiler directives in their native Move-style spelling (N-093): the
// attribute embed_always keeps `deploy_tag` in the locking script although
// no function reads it, and sighash(<FLAGS>) declares the BIP-143
// mode `spend_single` commits to.
module Directives {
    use runar::types::{Addr, ByteString, PubKey, Sig};
    use runar::crypto::{hash160, check_sig};

    struct Directives {
        pub_key_hash: Addr,
        #[embed_always]
        deploy_tag: ByteString,
    }

    public fun spend_all(contract: &Directives, sig: Sig, pub_key: PubKey) {
        assert!(hash160(pub_key) == contract.pub_key_hash, 0);
        assert!(check_sig(sig, pub_key), 0);
    }

    #[sighash(SINGLE | FORKID)]
    public fun spend_single(contract: &Directives, sig: Sig, pub_key: PubKey) {
        assert!(hash160(pub_key) == contract.pub_key_hash, 0);
        assert!(check_sig(sig, pub_key), 0);
    }
}

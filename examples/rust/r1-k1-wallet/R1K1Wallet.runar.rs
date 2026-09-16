// EXCLUDED FROM NATIVE RUST COMPILATION
//
// `cargo test` cannot compile this file as Rust, and it is not a missing mock:
// `len` and `substr` both ship in `packages/runar-rs` and both call sites
// below compile. One expression does not.
//
//   `substr(tx_preimage, len(tx_preimage) - 4, 4) == "41000000"` — rustc:
//   `can't compare `Vec<u8>` with `&str``. `"41000000"` is a Rúnar ByteString
//   LITERAL; this tier represents ByteString as `Vec<u8>`, and no `PartialEq`
//   between the two can be added from `packages/runar-rs` because neither type
//   is local to it (orphan rule). The Go tier does not hit this because
//   `runar.ByteString` is a `string` there.
//
//   `to_byte_string("41000000")` is valid Rust and emits byte-identical script
//   hex — measured, fold-on and fold-off — but it is NOT ANF-neutral: every
//   `.runar.rs` parser lowers it to a `toByteString` call node (checked in the
//   Go and Rust tiers) while the other eight surfaces of this fixture carry a
//   plain ByteString literal. The runner compares each format's ANF against the
//   ONE `expected-ir.json`, so the extra node fails `.runar.rs` and
//   regenerating the golden would fail the other eight. Making the nine
//   `.runar.rs` parsers fold `toByteString(<string literal>)` into a
//   ByteStringLiteral — which is what `spec/grammar.md` says it is — would
//   unblock this file and every other `.runar.rs` contract carrying a hex
//   literal, and is a seven-parser change, not a one-line one.
//
// Pinned by `examples/rust/native-exclusions/exclusions_test.rs`. Remove this
// header and the entry there in the same commit that wires the contract up.

use runar::prelude::*;

/// Hardware-backed P-256 primary spending with independent K1 recovery.
#[runar::contract]
pub struct R1K1Wallet {
    #[readonly]
    pub r1_salted_pub_key_hash: Addr,
    #[readonly]
    pub k1_pub_key_hash: Addr,
}

impl R1K1Wallet {
    pub fn spend_r1(
        &self,
        r1_sig: &ByteString,
        r1_pub_key: &ByteString,
        r1_salt: &ByteString,
        tx_preimage: &SigHashPreimage,
    ) {
        assert!(len(r1_salt) == 32);
        assert!(hash160(&cat(r1_pub_key, r1_salt)) == self.r1_salted_pub_key_hash);
        assert!(substr(tx_preimage, len(tx_preimage) - 4, 4) == "41000000");
        assert!(check_preimage(tx_preimage));
        assert!(verify_ecdsa_p256(&sha256(tx_preimage), r1_sig, r1_pub_key));
    }

    pub fn recover_k1(&self, k1_sig: &Sig, k1_pub_key: &PubKey) {
        assert!(hash160(k1_pub_key) == self.k1_pub_key_hash);
        assert!(check_sig(k1_sig, k1_pub_key));
    }
}

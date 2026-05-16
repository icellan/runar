// MultiSig2of3 — a 2-of-3 multi-signature contract.
//
// Funds are locked to three public keys. To spend, the unlocker must supply
// two valid ECDSA signatures from any two of the committed keys. The signing
// pair can be (pk1,pk2), (pk1,pk3), or (pk2,pk3); the order of the supplied
// signatures must match the order of the corresponding pubkeys in the
// committed array.
//
// `check_multi_sig([sig1, sig2], [self.pk1, self.pk2, self.pk3])` lowers to
// two `array_literal` ANF nodes — one for the signature array, one for the
// pubkey array. This is the canonical site where `array_literal` is emitted
// and is useful as a cross-compiler conformance fixture.
//
// Script layout:
//   Unlocking: <sig1> <sig2>
//   Locking:   OP_0 <sig1> <sig2> 2 <pk1> <pk2> <pk3> 3 OP_CHECKMULTISIG
//              OP_VERIFY

use runar::prelude::*;

#[runar::contract]
struct MultiSig2of3 {
    #[readonly]
    pk1: PubKey,
    #[readonly]
    pk2: PubKey,
    #[readonly]
    pk3: PubKey,
}

impl MultiSig2of3 {
    /// Unlock requires two valid signatures from any two of the three committed pubkeys.
    pub fn unlock(&self, sig1: &Sig, sig2: &Sig) {
        assert!(check_multi_sig([sig1, sig2], [&self.pk1, &self.pk2, &self.pk3]));
    }
}

use runar::prelude::*;

/// AnnotatedVault -- N-044 conformance fixture: a mutable variable-length
/// ByteString state field (`memo`) BEFORE a mutable PubKey (`owner`). Anyone
/// may replace the memo; only the owner may withdraw.
#[runar::contract]
pub struct AnnotatedVault {
    pub memo: ByteString,
    pub owner: PubKey,
    pub balance: Bigint,
}

impl AnnotatedVault {
    /// Replace the memo. Anyone can call.
    pub fn annotate(&mut self, next_memo: ByteString) {
        self.memo = next_memo;
    }

    /// Only the owner may spend.
    pub fn withdraw(&self, sig: &Sig) {
        assert!(check_sig(sig, &self.owner));
    }
}

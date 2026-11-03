use runar::prelude::*;

/// Notary -- F-352 second witness for the mutable-state shape
/// {ByteString, PubKey, bigint}, with the PubKey declared first.
#[runar::contract]
pub struct Notary {
    pub signer: PubKey,
    pub note: ByteString,
    pub seq: Bigint,
}

impl Notary {
    pub fn notarize(&mut self, sig: &Sig, next_note: ByteString) {
        assert!(check_sig(sig, &self.signer));
        self.note = next_note;
        self.seq = self.seq + 1;
    }
}

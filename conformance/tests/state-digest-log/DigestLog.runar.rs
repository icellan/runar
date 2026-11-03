use runar::prelude::*;

/// DigestLog -- F-352 second witness for the mutable-state shape {Ripemd160}.
#[runar::contract]
pub struct DigestLog {
    pub digest: Ripemd160,
}

impl DigestLog {
    pub fn replace(&mut self, new_digest: Ripemd160, version: Bigint) {
        assert!(version > 0);
        self.digest = new_digest;
    }
}

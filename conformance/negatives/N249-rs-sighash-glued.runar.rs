// N-244: the sighash marker glued to its flag list on the Rust DSL surface.
// Only .runar.ts honours the directive; every other surface must refuse ANY
// occurrence of the marker (N-039's rule), not just a word-bounded one, with
// the one shared "not supported by the Rust surface parser" message.
// Before N-244 every tier read the glued form as prose and compiled ALL|FORKID.
use runar::prelude::*;

#[runar::contract]
pub struct Counter {
    pub count: Bigint,
}

impl Counter {
    /// @sighashSINGLE|FORKID
    pub fn increment(&mut self) {
        self.count += 1;
    }
}

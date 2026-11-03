// N-153: a .runar.rs empty statement `;`. The TS reference refuses it; the
// Zig and Ruby tiers compiled it (Ruby as the literal 0). Every tier must
// refuse it; the TS reference says:
//   Unexpected token in expression: ';'
use runar::prelude::*;

#[runar::contract]
pub struct N187 {
    #[readonly]
    pub t: Bigint,
}

impl N187 {
    pub fn unlock(&self, x: Bigint) {
        ;
        assert!(x == self.t);
    }
}

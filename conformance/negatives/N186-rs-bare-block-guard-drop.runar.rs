// N-153: a .runar.rs bare block `{ ... }`. The TS reference refuses it; the
// Ruby tier alone accepted it, and DROPPED the statement after it: `{` became
// the literal 0, the block's `}` closed the method, and `assert!(x ==
// self.t);` was skipped, so the script (00517777) unlocked for any x. Every
// tier must refuse it; the TS reference says:
//   Unexpected token in expression: '{'
use runar::prelude::*;

#[runar::contract]
pub struct N186 {
    #[readonly]
    pub t: Bigint,
}

impl N186 {
    pub fn unlock(&self, x: Bigint) {
        { assert!(true); }
        assert!(x == self.t);
    }
}

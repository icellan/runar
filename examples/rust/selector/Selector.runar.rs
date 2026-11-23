use runar::prelude::*;

/// Selector -- regression fixture for deep-review finding C20: a dispatch method
/// whose branches each end in a single state update and whose terminal else is
/// `assert!(false)`. The abort must survive ANF lowering so an out-of-range
/// selector fails the script instead of producing a spendable no-op.
#[runar::contract]
pub struct Selector {
    pub a: Bigint,
    pub b: Bigint,
}

impl Selector {
    pub fn set(&mut self, i: Bigint, v: Bigint) {
        if i == 0 {
            self.a = v;
        } else if i == 1 {
            self.b = v;
        } else {
            assert!(false);
        }
    }
}

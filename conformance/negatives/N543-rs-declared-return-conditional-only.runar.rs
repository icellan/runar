// N-511: the .runar.rs spelling of N542. A return on only one arm compiled in
// all seven tiers, the fall-through path evaluating to OP_0. Every tier
// refuses:
//   Method 'helper' declares return type 'bigint' but does not return a value
//   on every path
use runar::prelude::*;

#[runar::contract]
struct Probe {
    #[readonly]
    target: Int,
}

impl Probe {
    fn helper(&self, x: Int) -> Int {
        if x > 0 {
            return x;
        }
    }

    pub fn verify(&self, a: Int) {
        assert!(self.helper(a) == self.target);
    }
}

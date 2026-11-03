// F-026: `256u8` does not fit its `u8` suffix, which rustc refuses
// ("literal out of range for `u8`", deny-by-default). Every tier must refuse
// with:
//   invalid Rust integer literal '256u8'
use runar::prelude::*;

#[runar::contract]
struct T {
    #[readonly]
    target: Int,
}

impl T {
    pub fn verify(&self, a: Int) {
        assert!(a > 256u8);
    }
}

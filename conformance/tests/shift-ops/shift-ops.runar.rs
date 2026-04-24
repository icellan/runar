use runar::prelude::*;

/// ShiftOps — Exercises bitshift operators `<<` and `>>` on Bigint values.
#[runar::contract]
pub struct ShiftOps {
    #[readonly]
    pub a: Bigint,
}

#[runar::methods(ShiftOps)]
impl ShiftOps {
    /// Apply left shift and right shift, then sanity-check the results.
    #[public]
    pub fn test_shift(&self) {
        let left = self.a << 3;
        let right = self.a >> 2;
        assert!(left >= 0 || left < 0);
        assert!(right >= 0 || right < 0);
    }
}

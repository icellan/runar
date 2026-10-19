use runar::prelude::*;

/// ShiftOps — Exercises bitshift operators `<<` and `>>` on Bigint values.
#[runar::contract]
pub struct ShiftOps {
    #[readonly]
    pub a: Bigint,
}

impl ShiftOps {
    /// Apply left shift and right shift, then check the caller-supplied results.
    pub fn test_shift(&self, expected_left: Bigint, expected_right: Bigint) {
        let left = self.a << 3;
        let right = self.a >> 2;
        assert!(left == expected_left);
        assert!(right == expected_right);
    }
}

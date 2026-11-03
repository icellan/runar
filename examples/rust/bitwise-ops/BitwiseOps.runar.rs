use runar::prelude::*;

/// BitwiseOps — Demonstrates bitwise and shift operators on Bigint values.
#[runar::contract]
pub struct BitwiseOps {
    #[readonly]
    pub a: Bigint,
    #[readonly]
    pub b: Bigint,
}

impl BitwiseOps {
    /// Check the caller-supplied shift results.
    pub fn test_shift(&self, expected_left: Bigint, expected_right: Bigint) {
        let left = self.a << 2;
        let right = self.a >> 1;
        assert!(left == expected_left);
        assert!(right == expected_right);
    }

    /// Check the caller-supplied AND/OR/XOR results; `~` is checked by double
    /// inversion and De Morgan's law (see the TS source for why).
    pub fn test_bitwise(&self, expected_and: Bigint, expected_or: Bigint, expected_xor: Bigint) {
        let and_result = self.a & self.b;
        let or_result = self.a | self.b;
        let xor_result = self.a ^ self.b;
        let not_result = ~self.a;
        assert!(and_result == expected_and);
        assert!(or_result == expected_or);
        assert!(xor_result == expected_xor);
        assert!(~not_result == self.a);
        assert!(~(self.a | self.b) == (not_result & ~self.b));
    }
}

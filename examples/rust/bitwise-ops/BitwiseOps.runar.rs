use runar::prelude::*;

/// BitwiseOps — Demonstrates bitwise and shift operators on Bigint values.
#[runar::contract]
pub struct BitwiseOps {
    #[readonly]
    pub a: Bigint,
    #[readonly]
    pub b: Bigint,
}

#[runar::methods(BitwiseOps)]
impl BitwiseOps {
    /// Verify shift operators compile and run.
    #[public]
    pub fn test_shift(&self) {
        let left = self.a << 2;
        let right = self.a >> 1;
        assert!(left >= 0 || left < 0);
        assert!(right >= 0 || right < 0);
        assert!(true);
    }

    /// Verify bitwise operators compile and run.
    #[public]
    pub fn test_bitwise(&self) {
        let and_result = self.a & self.b;
        let or_result = self.a | self.b;
        let xor_result = self.a ^ self.b;
        let not_result = ~self.a;
        assert!(and_result >= 0 || and_result < 0);
        assert!(or_result >= 0 || or_result < 0);
        assert!(xor_result >= 0 || xor_result < 0);
        assert!(not_result >= 0 || not_result < 0);
        assert!(true);
    }
}

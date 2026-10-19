// BitwiseOps — Demonstrates bitwise and shift operators on bigint values.
module BitwiseOps {
    struct BitwiseOps {
        a: bigint,
        b: bigint,
    }

    // Check the caller-supplied shift results.
    public fun test_shift(contract: &BitwiseOps, expected_left: bigint, expected_right: bigint) {
        let left: bigint = contract.a << 2;
        let right: bigint = contract.a >> 1;
        assert!(left == expected_left, 0);
        assert!(right == expected_right, 0);
    }

    // Check the caller-supplied AND/OR/XOR results; `~` is checked by double
    // inversion and De Morgan's law (see the TS source for why).
    public fun test_bitwise(contract: &BitwiseOps, expected_and: bigint, expected_or: bigint, expected_xor: bigint) {
        let and_result: bigint = contract.a & contract.b;
        let or_result: bigint = contract.a | contract.b;
        let xor_result: bigint = contract.a ^ contract.b;
        let not_result: bigint = ~contract.a;
        assert!(and_result == expected_and, 0);
        assert!(or_result == expected_or, 0);
        assert!(xor_result == expected_xor, 0);
        assert!(~not_result == contract.a, 0);
        assert!(~(contract.a | contract.b) == (not_result & ~contract.b), 0);
    }
}

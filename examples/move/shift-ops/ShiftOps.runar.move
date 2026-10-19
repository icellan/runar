// ShiftOps — Exercises bitshift operators `<<` and `>>` on bigint values.
module ShiftOps {
    struct ShiftOps {
        a: bigint,
    }

    // Apply left shift and right shift, then check the caller-supplied results.
    public fun test_shift(contract: &ShiftOps, expected_left: bigint, expected_right: bigint) {
        let left: bigint = contract.a << 3;
        let right: bigint = contract.a >> 2;
        assert!(left == expected_left, 0);
        assert!(right == expected_right, 0);
    }
}

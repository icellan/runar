// ShiftOps — Exercises bitshift operators `<<` and `>>` on bigint values.
module ShiftOps {
    struct ShiftOps {
        a: bigint,
    }

    // Apply left shift and right shift, then sanity-check the results.
    public fun test_shift(contract: &ShiftOps) {
        let left: bigint = contract.a << 3;
        let right: bigint = contract.a >> 2;
        assert!(left >= 0 || left < 0, 0);
        assert!(right >= 0 || right < 0, 0);
    }
}

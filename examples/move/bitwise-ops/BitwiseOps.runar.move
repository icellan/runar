// BitwiseOps — Demonstrates bitwise and shift operators on bigint values.
module BitwiseOps {
    struct BitwiseOps {
        a: bigint,
        b: bigint,
    }

    // Verify shift operators compile and run.
    public fun test_shift(contract: &BitwiseOps) {
        let left: bigint = contract.a << 2;
        let right: bigint = contract.a >> 1;
        assert!(left >= 0 || left < 0, 0);
        assert!(right >= 0 || right < 0, 0);
        assert!(true, 0);
    }

    // Verify bitwise operators compile and run.
    public fun test_bitwise(contract: &BitwiseOps) {
        let and_result: bigint = contract.a & contract.b;
        let or_result: bigint = contract.a | contract.b;
        let xor_result: bigint = contract.a ^ contract.b;
        let not_result: bigint = ~contract.a;
        assert!(and_result >= 0 || and_result < 0, 0);
        assert!(or_result >= 0 || or_result < 0, 0);
        assert!(xor_result >= 0 || xor_result < 0, 0);
        assert!(not_result >= 0 || not_result < 0, 0);
        assert!(true, 0);
    }
}

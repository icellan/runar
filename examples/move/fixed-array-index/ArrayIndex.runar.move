// ArrayIndex — Move-style port of
// `examples/ts/fixed-array-index/ArrayIndex.runar.ts`.
//
// Exercises the synthetic generic `FixedArray<T, N>` together with a RUNTIME
// index read `self.table[i]`.
module ArrayIndex {
    use runar::SmartContract;

    struct ArrayIndex {
        table: FixedArray<bigint, 4> = [10, 20, 30, 40],
    }

    public fun lookup(i: bigint, expected: bigint) {
        assert!(self.table[i] == expected, 0);
    }
}

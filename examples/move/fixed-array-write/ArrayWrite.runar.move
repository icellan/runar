// ArrayWrite — Move-style port of
// `examples/ts/fixed-array-write/ArrayWrite.runar.ts`.
module ArrayWrite {
    use runar::StatefulSmartContract;

    resource struct ArrayWrite {
        table: &mut FixedArray<bigint, 4> = [0, 0, 0, 0],
    }

    public fun bump(i: bigint) {
        self.table[i] = self.table[i] + 1;
        assert!(true, 0);
    }
}

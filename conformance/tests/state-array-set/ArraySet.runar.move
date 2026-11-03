// ArraySet -- Move-style port of ArraySet.runar.ts.
module ArraySet {
    use runar::StatefulSmartContract;

    resource struct ArraySet {
        slots: &mut FixedArray<bigint, 4> = [0, 0, 0, 0],
    }

    public fun put(i: bigint, v: bigint) {
        self.slots[i] = v;
        assert!(true, 0);
    }
}

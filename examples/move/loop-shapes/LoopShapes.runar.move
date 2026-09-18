// LoopShapes -- Move-style port. A NON-ZERO loop start, ascending (R-102).
module LoopShapes {
    use runar::types::{Int};

    struct LoopShapes {
        target: Int,
    }

    public fun verify(contract: &LoopShapes, seed: Int) {
        let acc: Int = seed;
        let i: Int = 3;
        while (i < 7) {
            acc = acc + i;
            i = i + 1;
        };
        assert_eq!(acc, contract.target);
    }
}

// CountdownLoop -- Move-style port. `step = -1` (R-102).
//
// Move has no C-style `for`, so a bounded loop is an induction variable
// declared just before a `while`, and the step is the last statement of the
// body. The fold that recognises that pattern matched `i = i + ...` only, so
// THIS contract -- and every counting-down Move contract -- compiled to a
// locking script with the loop body absent and no diagnostic at all.
// See CountdownLoop.runar.ts.
module CountdownLoop {
    use runar::types::{Int};

    struct CountdownLoop {
        target: Int,
    }

    public fun verify(contract: &CountdownLoop, seed: Int) {
        let acc: Int = seed;
        let i: Int = 5;
        while (i > 1) {
            acc = acc + i;
            i = i - 1;
        };
        assert_eq!(acc, contract.target);
    }
}

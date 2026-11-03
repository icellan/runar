// N-491: TS surface-parser operand anchor parity. A `!` applied to a bigint identifier.
// TS must anchor the refusal on this surface exactly where it does on .runar.ts
// (see n491-operand-anchor-surface-matrix.test.ts).
module Anchor {
    use runar::types::{Int};

    struct Anchor {
        t: Int,
    }

    public fun go(contract: &Anchor, x: Int, flag: bool) {
        assert!(!x, 0);
    }
}

// N-491: TS surface-parser operand anchor parity. A boolean identifier as the right operand of `<`.
// TS must anchor the refusal on this surface exactly where it does on .runar.ts
// (see n491-operand-anchor-surface-matrix.test.ts).
module Anchor {
    use runar::types::{Int};

    struct Anchor {
        t: Int,
    }

    public fun go(contract: &Anchor, x: Int, flag: bool) {
        assert!(x < flag, 0);
    }
}

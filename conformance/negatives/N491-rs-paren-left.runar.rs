// N-491: TS surface-parser operand anchor parity. A parenthesised bigint composite as the left operand of `&&`.
// TS must anchor the refusal on this surface exactly where it does on .runar.ts
// (see n491-operand-anchor-surface-matrix.test.ts).
use runar::prelude::*;

#[runar::contract]
struct Anchor {
    #[readonly]
    t: Int,
}

impl Anchor {
    pub fn go(&self, x: Int, flag: bool) {
        assert!((x + 1) && flag);
    }
}

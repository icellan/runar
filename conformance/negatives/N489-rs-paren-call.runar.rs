// N-489: typecheck diagnostic anchor parity. A bigint composite whose first token is a parenthesised call, as the left operand of `&&`.
// Every tier must anchor the refusal where the TypeScript reference does
// (see n233-diagnostic-anchor-parity.test.ts).
use runar::prelude::*;

#[runar::contract]
struct Anchor {
    #[readonly]
    t: Int,
}

impl Anchor {
    pub fn go(&self, x: Int, flag: bool) {
        assert!((abs(x)) + 1 && flag);
    }
}

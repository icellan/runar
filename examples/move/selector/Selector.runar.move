// Selector -- regression fixture for deep-review finding C20: a dispatch
// method whose branches each end in a single state update and whose terminal
// `else` is `assert!(false, 0)`. The abort must survive ANF lowering so an
// out-of-range selector fails the script instead of producing a spendable
// no-op state continuation.
module Selector {
    resource struct Selector {
        a: &mut bigint,
        b: &mut bigint,
    }

    public fun set(contract: &mut Selector, i: bigint, v: bigint) {
        if (i == 0) {
            contract.a = v;
        } else if (i == 1) {
            contract.b = v;
        } else {
            assert!(false, 0);
        };
    }
}

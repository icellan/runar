// N-153: `abort 0;` is not part of the .runar.move surface. The TS reference
// refuses it; the Zig tier compiled it as assert(false). Every tier must
// refuse it; the TS reference says:
//   Undefined variable 'abort'
module N189 {
    use runar::SmartContract;
    use runar::types::{Int};

    struct N189 {
        t: Int,
    }

    public fun unlock(contract: &N189, x: Int) {
        if (x != contract.t) { abort 0; };
        assert!(true, 0);
    }
}

module IfWithoutElse {
    use runar::types::{Int};

    resource struct IfWithoutElse {
        threshold: Int,
    }

    public fun check(contract: &IfWithoutElse, a: Int, b: Int) {
        let count: Int = 0;
        if (a > contract.threshold) {
            count = count + 1;
        };
        if (b > contract.threshold) {
            count = count + 1;
        };
        assert!(count > 0, 0);
    }
}

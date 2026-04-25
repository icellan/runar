module IfElse {
    use runar::types::{Int};

    struct IfElse {
        limit: Int,
    }

    public fun check(contract: &IfElse, value: Int, mode: bool) {
        let result: Int = 0;
        if (mode) {
            result = value + contract.limit;
        } else {
            result = value - contract.limit;
        };
        assert!(result > 0, 0);
    }
}

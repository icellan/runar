module BooleanLogic {
    use runar::types::{Int};

    resource struct BooleanLogic {
        threshold: Int,
    }

    public fun verify(contract: &BooleanLogic, a: Int, b: Int, flag: bool) {
        let a_above_threshold = a > contract.threshold;
        let b_above_threshold = b > contract.threshold;
        let both_above = a_above_threshold && b_above_threshold;
        let either_above = a_above_threshold || b_above_threshold;
        let not_flag = !flag;
        assert!(both_above || (either_above && not_flag), 0);
    }
}

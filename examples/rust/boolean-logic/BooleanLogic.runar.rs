use runar::prelude::*;

#[runar::contract]
struct BooleanLogic {
    #[readonly]
    threshold: Int,
}

#[runar::methods(BooleanLogic)]
impl BooleanLogic {
    #[public]
    fn verify(&self, a: Int, b: Int, flag: bool) {
        let a_above_threshold = a > self.threshold;
        let b_above_threshold = b > self.threshold;
        let both_above = a_above_threshold && b_above_threshold;
        let either_above = a_above_threshold || b_above_threshold;
        let not_flag = !flag;
        assert!(both_above || (either_above && not_flag));
    }
}

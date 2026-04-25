use runar::prelude::*;

#[runar::contract]
struct IfWithoutElse {
    #[readonly]
    threshold: Int,
}

#[runar::methods(IfWithoutElse)]
impl IfWithoutElse {
    #[public]
    fn check(&self, a: Int, b: Int) {
        let mut count: Int = 0;
        if a > self.threshold {
            count = count + 1;
        }
        if b > self.threshold {
            count = count + 1;
        }
        assert!(count > 0);
    }
}

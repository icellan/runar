use runar::prelude::*;

#[runar::contract]
struct IfElse {
    #[readonly]
    limit: Int,
}

impl IfElse {
    pub fn check(&self, value: Int, mode: bool) {
        let mut result: Int = 0;
        if mode {
            result = value + self.limit;
        } else {
            result = value - self.limit;
        }
        assert!(result > 0);
    }
}

use runar::prelude::*;

#[runar::contract]
struct Stateful {
    count: Int,
    #[readonly]
    max_count: Int,
}

impl Stateful {
    pub fn increment(&mut self, amount: Int) {
        self.count = self.count + amount;
        assert!(self.count <= self.max_count);
    }

    pub fn reset(&mut self) {
        self.count = 0;
    }
}

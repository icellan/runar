use runar::prelude::*;

#[runar::contract]
struct PropertyInitializers {
    count: Int,
    #[readonly]
    max_count: Int,
    #[readonly]
    active: Bool,
}

impl PropertyInitializers {
    fn init(&mut self) {
        self.count = 0;
        self.active = true;
    }

    pub fn increment(&mut self, amount: Int) {
        assert!(self.active);
        self.count = self.count + amount;
        assert!(self.count <= self.max_count);
    }

    pub fn reset(&mut self) {
        self.count = 0;
    }
}

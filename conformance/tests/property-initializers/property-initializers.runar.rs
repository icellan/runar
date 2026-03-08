use runar::prelude::*;

#[runar::contract]
struct PropertyInitializers {
    count: Int,
    #[readonly]
    max_count: Int,
    #[readonly]
    active: Bool,
}

#[runar::methods(PropertyInitializers)]
impl PropertyInitializers {
    fn init(&mut self) {
        self.count = 0;
        self.active = true;
    }

    #[public]
    fn increment(&mut self, amount: Int) {
        assert!(self.active);
        self.count = self.count + amount;
        assert!(self.count <= self.max_count);
    }

    #[public]
    fn reset(&mut self) {
        self.count = 0;
    }
}

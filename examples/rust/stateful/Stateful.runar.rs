use runar::prelude::*;

#[runar::contract]
struct Stateful {
    count: Int,
    #[readonly]
    max_count: Int,
}

#[runar::methods(Stateful)]
impl Stateful {
    #[public]
    fn increment(&mut self, amount: Int) {
        self.count = self.count + amount;
        assert!(self.count <= self.max_count);
    }

    #[public]
    fn reset(&mut self) {
        self.count = 0;
    }
}

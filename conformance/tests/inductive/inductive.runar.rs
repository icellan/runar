use runar::prelude::*;

#[runar::contract]
struct Inductive {
    count: Int,
    #[readonly]
    max_count: Int,
}

#[runar::methods(Inductive)]
impl Inductive {
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

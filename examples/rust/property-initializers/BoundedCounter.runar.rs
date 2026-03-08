use runar::prelude::*;

/// BoundedCounter — demonstrates property initializers in Rust format.
///
/// Properties assigned in the `init()` method are excluded from the
/// auto-generated constructor. Only `max_count` needs to be provided
/// at deploy time.
#[runar::contract]
pub struct BoundedCounter {
    pub count: Bigint,
    #[readonly]
    pub max_count: Bigint,
    #[readonly]
    pub active: bool,
}

#[runar::methods(BoundedCounter)]
impl BoundedCounter {
    pub fn init(&mut self) {
        self.count = 0;
        self.active = true;
    }

    #[public]
    pub fn increment(&mut self, amount: Bigint) {
        assert!(self.active);
        self.count = self.count + amount;
        assert!(self.count <= self.max_count);
    }

    #[public]
    pub fn reset(&mut self) {
        self.count = 0;
    }
}

use runar::prelude::*;

/// DataOutputTest -- Exercises add_data_output alongside state continuation.
#[runar::contract]
pub struct DataOutputTest {
    pub count: Bigint,
}

#[runar::methods(DataOutputTest)]
impl DataOutputTest {
    /// Increment the counter and attach an arbitrary data output whose bytes
    /// are committed to by the state continuation hash.
    #[public]
    pub fn publish(&mut self, payload: ByteString) {
        self.count = self.count + 1;
        self.add_data_output(0, payload);
    }
}

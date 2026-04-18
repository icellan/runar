use runar::prelude::*;

/// RawOutputTest -- Exercises add_raw_output alongside add_output for stateful
/// contracts.
#[runar::contract]
pub struct RawOutputTest {
    pub count: Bigint,
}

#[runar::methods(RawOutputTest)]
impl RawOutputTest {
    /// Emit a raw output with arbitrary script bytes, then increment the
    /// counter and emit the state continuation.
    #[public]
    pub fn send_to_script(&mut self, script_bytes: ByteString) {
        self.add_raw_output(1000, script_bytes);
        self.count = self.count + 1;
        self.add_output(0, self.count);
    }
}

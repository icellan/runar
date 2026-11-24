use runar::prelude::*;

/// StatefulTerminalLoop -- a TERMINAL stateful method (no state write, so no
/// injected continuation assert) whose bounded loop of asserts is followed by
/// a final assert, which is the script result. Without it the method is
/// refused in every tier (conformance/negatives N547).
#[runar::contract]
pub struct StatefulTerminalLoop {
    pub floor: Bigint,
    pub count: Bigint,
}

impl StatefulTerminalLoop {
    pub fn close(&mut self, x: Bigint) {
        for i in 0..2 {
            assert!(x >= self.floor + i);
        }
        assert!(x > self.count);
    }
}

use runar::prelude::*;

/// ArraySet -- Rust DSL port of ArraySet.runar.ts.
#[runar::stateful_contract]
pub struct ArraySet {
    pub slots: [Bigint; 4],
    pub tx_preimage: SigHashPreimage,
}

impl ArraySet {
    pub fn init(&mut self) {
        self.slots = [0, 0, 0, 0];
    }

    pub fn put(&mut self, i: Bigint, v: Bigint) {
        self.slots[i] = v;
        assert!(true);
    }
}

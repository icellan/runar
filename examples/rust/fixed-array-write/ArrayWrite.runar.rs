use runar::prelude::*;

/// ArrayWrite -- Rust DSL port of
/// `examples/ts/fixed-array-write/ArrayWrite.runar.ts`.
#[runar::stateful_contract]
pub struct ArrayWrite {
    pub table: [Bigint; 4],
    pub tx_preimage: SigHashPreimage,
}

impl ArrayWrite {
    pub fn init(&mut self) {
        self.table = [0, 0, 0, 0];
    }

    pub fn bump(&mut self, i: Bigint) {
        self.table[i] += 1;
        assert!(true);
    }
}

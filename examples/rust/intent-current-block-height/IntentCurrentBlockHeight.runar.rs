use runar::prelude::*;

/// IntentCurrentBlockHeight -- exercises the `current_block_height`
/// shorthand, which is pure source-level sugar for
/// `extract_locktime(self.tx_preimage)`.
#[runar::contract]
pub struct IntentCurrentBlockHeight {
    #[readonly]
    pub deadline: Bigint,
    pub count: Bigint,
}

impl IntentCurrentBlockHeight {
    pub fn spend(&mut self) {
        let h = current_block_height();
        assert!(h <= self.deadline);
        self.count = self.count + 1;
    }
}

use runar::prelude::*;

/// BranchedReadonlyLen -- exercises a state-mutating if/else branched
/// on a read-only intrinsic value (`len`).
#[runar::contract]
pub struct BranchedReadonlyLen {
    pub count: Bigint,
    pub tag: ByteString,
}

impl BranchedReadonlyLen {
    pub fn spend(&mut self, scratch: ByteString) {
        if len(scratch) > 0 {
            self.count = self.count + 1;
            self.tag = scratch;
        } else {
            self.count = self.count - 1;
            self.tag = 0x3030;
        }
        self.add_output(1000, self.count, self.tag);
    }
}

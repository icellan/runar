use runar::prelude::*;

/// IntentPrevOutputScript -- exercises the `extract_prev_output_script`
/// intent intrinsic. Reads input 0's previous-output locking script via
/// the witness-bridge pattern and asserts it is non-empty after the
/// hash-equality check the intrinsic emits internally.
#[runar::contract]
pub struct IntentPrevOutputScript {
    #[readonly]
    pub expected_hash: ByteString,
    pub count: Bigint,
}

impl IntentPrevOutputScript {
    pub fn bind(&mut self) {
        let s = extract_prev_output_script(0, self.expected_hash);
        assert!(len(s) > 0);
        self.count = self.count + 1;
    }
}

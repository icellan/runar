use runar::prelude::*;

/// IntentPrevOutputScript -- exercises the `extract_prev_output_script`
/// intent intrinsic.
///
/// It does NOT read input 0 (W6 / GhostInput). The intrinsic asserts that a
/// caller-supplied byte string hashes to `expectedHash` and returns it; this
/// contract then asserts the string is non-empty. The first argument is a
/// compile-time label naming the auto-injected witness parameter
/// `_prevOutScript_0`, which the unlocking script supplies. There is no vin
/// lookup, no parent transaction and no input-count check in the emitted
/// script. For a construction that binds a specific companion INPUT, see
/// `examples/ts/companion-verifier/`.
#[runar::contract]
pub struct IntentPrevOutputScript {
    #[readonly]
    pub expected_hash: ByteString,
    pub count: Bigint,
}

impl IntentPrevOutputScript {
    pub fn bind(&mut self) {
        let s = extract_prev_output_script(0, &self.expected_hash);
        assert!(len(&s) > 0);
        self.count = self.count + 1;
    }
}

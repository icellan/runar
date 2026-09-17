// IntentPrevOutputScript -- exercises the `extractPrevOutputScript`
// intent intrinsic.
//
// It does NOT read input 0 (W6 / GhostInput). The intrinsic asserts that a
// caller-supplied byte string hashes to `expectedHash` and returns it; this
// contract then asserts the string is non-empty. The first argument is a
// compile-time label naming the auto-injected witness parameter
// `_prevOutScript_0`, which the unlocking script supplies. There is no vin
// lookup, no parent transaction and no input-count check in the emitted
// script. For a construction that binds a specific companion INPUT, see
// `examples/ts/companion-verifier/`.
module IntentPrevOutputScript {
    use runar::types::{ByteString};

    resource struct IntentPrevOutputScript {
        expectedHash: ByteString,
        count: &mut bigint,
    }

    public fun bind(contract: &mut IntentPrevOutputScript) {
        let s: ByteString = extractPrevOutputScript(0, contract.expectedHash);
        assert!(len(s) > 0, 0);
        contract.count = contract.count + 1;
    }
}

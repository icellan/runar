// IntentPrevOutputScript -- exercises the `extractPrevOutputScript`
// intent intrinsic. Reads input 0's previous-output locking script
// via the witness-bridge pattern and asserts it is non-empty after
// the hash-equality check the intrinsic emits internally.
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

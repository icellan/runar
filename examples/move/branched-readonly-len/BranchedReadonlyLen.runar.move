// BranchedReadonlyLen -- exercises a state-mutating if/else branched
// on a read-only intrinsic value (`len`).
module BranchedReadonlyLen {
    use runar::types::{ByteString};

    resource struct BranchedReadonlyLen {
        count: &mut bigint,
        tag: &mut ByteString,
    }

    public fun spend(contract: &mut BranchedReadonlyLen, scratch: ByteString) {
        if (len(scratch) > 0) {
            contract.count = contract.count + 1;
            contract.tag = scratch;
        } else {
            contract.count = contract.count - 1;
            contract.tag = 0x3030;
        };
        contract.addOutput(1000, contract.count, contract.tag);
    }
}

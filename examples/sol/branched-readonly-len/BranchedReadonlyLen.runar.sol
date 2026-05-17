pragma runar ^0.1.0;

/// @title BranchedReadonlyLen
/// @notice Exercises a state-mutating if/else branched on a read-only
/// intrinsic value (`len`).
contract BranchedReadonlyLen is StatefulSmartContract {
    bigint count;
    ByteString tag;

    constructor(bigint _count, ByteString _tag) {
        count = _count;
        tag = _tag;
    }

    function spend(ByteString scratch) public {
        if (len(scratch) > 0) {
            this.count = this.count + 1;
            this.tag = scratch;
        } else {
            this.count = this.count - 1;
            this.tag = 0x3030;
        }
        this.addOutput(1000, this.count, this.tag);
    }
}

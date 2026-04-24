pragma runar ^0.1.0;

/// @title DataOutputTest
/// @notice Exercises addDataOutput alongside state continuation.
contract DataOutputTest is StatefulSmartContract {
    bigint count;

    constructor(bigint _count) {
        count = _count;
    }

    /// @notice Increment the counter and attach an arbitrary data output whose
    /// bytes are committed to by the state continuation hash.
    function publish(ByteString payload) public {
        this.count = this.count + 1;
        this.addDataOutput(0, payload);
    }
}

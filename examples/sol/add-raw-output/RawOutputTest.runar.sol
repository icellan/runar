pragma runar ^0.1.0;

/// @title RawOutputTest
/// @notice Exercises addRawOutput alongside addOutput for stateful contracts.
contract RawOutputTest is StatefulSmartContract {
    bigint count;

    constructor(bigint _count) {
        count = _count;
    }

    /// @notice Emit a raw output with arbitrary script bytes, then increment
    /// the counter and emit the state continuation.
    function sendToScript(ByteString scriptBytes) public {
        this.addRawOutput(1000, scriptBytes);
        this.count = this.count + 1;
        this.addOutput(0, this.count);
    }
}

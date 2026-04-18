// RawOutputTest -- Exercises add_raw_output alongside add_output for stateful
// contracts.
module RawOutputTest {
    resource struct RawOutputTest {
        count: &mut bigint,
    }

    // Emit a raw output with arbitrary script bytes, then increment the counter
    // and emit the state continuation.
    public fun send_to_script(contract: &mut RawOutputTest, script_bytes: ByteString) {
        contract.add_raw_output(1000, script_bytes);
        contract.count = contract.count + 1;
        contract.add_output(0, contract.count);
    }
}

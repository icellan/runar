// DataOutputTest -- Exercises add_data_output alongside state continuation.
module DataOutputTest {
    resource struct DataOutputTest {
        count: &mut bigint,
    }

    // Increment the counter and attach an arbitrary data output whose
    // bytes are committed to by the state continuation hash.
    public fun publish(contract: &mut DataOutputTest, payload: ByteString) {
        contract.count = contract.count + 1;
        contract.add_data_output(0, payload);
    }
}

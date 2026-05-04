// ConditionalDataOutput -- Audit regression: a stateful method that
// emits a data output on a conditional branch must keep the canonical
// single-output `computeStateOutput` state continuation on every path.
//
// See `conformance/tests/conditional-data-output-stateful/` for the full
// rationale; the cross-format ports must produce identical Bitcoin Script.
module ConditionalDataOutput {
    resource struct ConditionalDataOutput {
        amount: &mut bigint,
    }

    // The canonical bug: add_data_output is wrapped in a branch.
    // The compiler must register the if's value as a DATA output ref
    // (not a state output ref) so that the parent method's continuation
    // hash keeps `compute_state_output`.
    public fun pay(contract: &mut ConditionalDataOutput, flag: bool, payload: ByteString) {
        contract.amount = contract.amount + 1;
        if (flag) {
            contract.add_data_output(0, payload);
        };
        assert!(true, 0);
    }
}

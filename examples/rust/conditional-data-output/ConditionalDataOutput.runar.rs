use runar::prelude::*;

/// ConditionalDataOutput -- Audit regression: a stateful method that
/// emits a data output on a conditional branch must keep the canonical
/// single-output `computeStateOutput` state continuation on every path.
///
/// See `conformance/tests/conditional-data-output-stateful/` for the full
/// rationale; the cross-format ports must produce identical Bitcoin Script.
#[runar::contract]
pub struct ConditionalDataOutput {
    pub amount: Bigint,
}

#[runar::methods(ConditionalDataOutput)]
impl ConditionalDataOutput {
    /// The canonical bug: `add_data_output` is wrapped in a branch.
    /// The compiler must register the if's value as a DATA output ref
    /// (not a state output ref) so that the parent method's continuation
    /// hash keeps `compute_state_output`.
    #[public]
    pub fn pay(&mut self, flag: bool, payload: ByteString) {
        self.amount = self.amount + 1;
        if flag {
            self.add_data_output(0, payload);
        }
        assert!(true);
    }
}

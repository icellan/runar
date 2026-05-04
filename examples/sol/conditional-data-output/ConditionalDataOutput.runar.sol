// ConditionalDataOutput -- Audit regression: a stateful method that
// emits a data output on a conditional branch must keep the canonical
// single-output `computeStateOutput` state continuation on every path.
//
// See `conformance/tests/conditional-data-output-stateful/` for the full
// rationale; the cross-format ports must produce identical Bitcoin Script.

pragma runar ^0.1.0;

contract ConditionalDataOutput is StatefulSmartContract {
    bigint amount;

    constructor(bigint _amount) {
        amount = _amount;
    }

    // The canonical bug: addDataOutput is wrapped in a branch.
    // The compiler must register the if's value as a DATA output ref
    // (not a state output ref) so that the parent method's continuation
    // hash keeps `computeStateOutput`.
    function pay(bool flag, ByteString payload) public {
        this.amount = this.amount + 1;
        if (flag) {
            this.addDataOutput(0, payload);
        }
        require(true);
    }
}

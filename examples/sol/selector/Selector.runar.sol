pragma runar ^0.1.0;

/// @title Selector
/// @notice Regression fixture for deep-review finding C20 -- a dispatch method
/// whose branches each end in a single state update and whose terminal `else`
/// is `require(false)`. The abort must survive ANF lowering so an out-of-range
/// selector fails the script instead of producing a spendable no-op.
contract Selector is StatefulSmartContract {
    bigint a;
    bigint b;

    constructor(bigint _a, bigint _b) {
        a = _a;
        b = _b;
    }

    function set(bigint i, bigint v) public {
        if (i == 0) {
            this.a = v;
        } else if (i == 1) {
            this.b = v;
        } else {
            require(false);
        }
    }
}

pragma runar ^0.1.0;

/// @title IntentCurrentBlockHeight
/// @notice Exercises the `currentBlockHeight` shorthand, which is pure
/// source-level sugar for `extractLocktime(this.txPreimage)`.
contract IntentCurrentBlockHeight is StatefulSmartContract {
    bigint immutable deadline;
    bigint count;

    constructor(bigint _deadline, bigint _count) {
        deadline = _deadline;
        count = _count;
    }

    function spend() public {
        bigint h = currentBlockHeight();
        require(h <= this.deadline);
        this.count = this.count + 1;
    }
}

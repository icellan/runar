pragma runar ^0.1.0;

/// @title IntentOutputP2PKH
/// @notice Exercises the `requireOutputP2PKH` intent intrinsic.
/// Asserts that output 0 of the spending transaction is a standard
/// P2PKH output paying exactly `bondAmount` satoshis to `bondPKH`.
contract IntentOutputP2PKH is StatefulSmartContract {
    ByteString immutable bondPKH;
    bigint immutable bondAmount;
    bigint count;

    constructor(ByteString _bondPKH, bigint _bondAmount, bigint _count) {
        bondPKH = _bondPKH;
        bondAmount = _bondAmount;
        count = _count;
    }

    function payBond() public {
        requireOutputP2PKH(0, this.bondPKH, this.bondAmount);
        this.count = this.count + 1;
    }
}

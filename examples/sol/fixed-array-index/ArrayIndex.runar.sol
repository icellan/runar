pragma runar ^0.1.0;

/// ArrayIndex — Solidity-like port of
/// `examples/ts/fixed-array-index/ArrayIndex.runar.ts`.
///
/// Exercises the flat fixed-array surface syntax `bigint[4]` together with a
/// RUNTIME index read `this.table[i]`.
contract ArrayIndex is SmartContract {
    bigint[4] immutable table = [10, 20, 30, 40];

    constructor() {}

    function lookup(bigint i, bigint expected) public {
        require(this.table[i] == expected);
    }
}

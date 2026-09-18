pragma runar ^0.1.0;

/// ArrayWrite — Solidity-like port of
/// `examples/ts/fixed-array-write/ArrayWrite.runar.ts`.
contract ArrayWrite is StatefulSmartContract {
    bigint[4] table = [0, 0, 0, 0];

    constructor() {}

    function bump(bigint i) public {
        this.table[i]++;
        require(true);
    }
}

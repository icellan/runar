pragma runar ^0.1.0;

/// ArraySet -- Solidity-like port of ArraySet.runar.ts.
contract ArraySet is StatefulSmartContract {
    bigint[4] slots = [0, 0, 0, 0];

    constructor() {}

    function put(bigint i, bigint v) public {
        this.slots[i] = v;
        require(true);
    }
}

// N-132: an EMPTY for-update on `.runar.sol`. The TS reference's Solidity
// parser always parses an update expression there and refuses the `)`:
//   Unexpected token in expression: ')'
// Zig alone left the slot empty and compiled it (byte-identical to `i++`).
// Every tier must refuse it.
pragma runar ^0.1.0;

contract N181 is StatefulSmartContract {
    int count;

    constructor(int _count) {
        count = _count;
    }

    function unlock(int expected) public {
        int acc = 0;
        for (int i = 0; i < 3; ) {
            acc = acc + i;
        }
        require(acc == expected);
    }
}

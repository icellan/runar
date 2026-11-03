// N-133: a compound assignment in a `.runar.sol` for-update. The TS
// reference's Solidity parser takes one expression (plus an optional postfix
// `++`/`--`) there and then expects `)`:
//   Expected ')', got '+='
// Rust alone desugared it into `i = i + 1` and compiled it (byte-identical to
// `i++`). Every tier must refuse it.
pragma runar ^0.1.0;

contract N172 is StatefulSmartContract {
    int count;

    constructor(int _count) {
        count = _count;
    }

    function unlock(int expected) public {
        int acc = 0;
        for (int i = 0; i < 3; i += 1) {
            acc = acc + i;
        }
        require(acc == expected);
    }
}

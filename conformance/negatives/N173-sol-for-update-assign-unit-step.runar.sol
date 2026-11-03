// N-133: a plain assignment in a `.runar.sol` for-update. The TS reference's
// Solidity parser refuses it at the `)` it expects after the update:
//   Expected ')', got '='
// Rust alone accepted it and compiled it (byte-identical to `i++`). Every tier
// must refuse it.
pragma runar ^0.1.0;

contract N173 is StatefulSmartContract {
    int count;

    constructor(int _count) {
        count = _count;
    }

    function unlock(int expected) public {
        int acc = 0;
        for (int i = 0; i < 3; i = i + 1) {
            acc = acc + i;
        }
        require(acc == expected);
    }
}

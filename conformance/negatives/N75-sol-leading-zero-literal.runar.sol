// F-026: "Octal literals do not exist in Solidity and leading zeros are
// invalid" (Solidity docs). Pre-fix every tier accepted `012`, with three
// different values: 12 (ts, rust, zig, java), 10 (go, ruby), 0 (python).
// Every tier must refuse with:
//   invalid Solidity integer literal '012'
pragma runar ^0.1.0;

contract T is SmartContract {
    int immutable target;

    constructor(int _target) {
        target = _target;
    }

    function verify(int a) public {
        require(a > 012);
    }
}

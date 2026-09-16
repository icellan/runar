pragma runar ^0.1.0;

/// CountdownLoop — Solidity-like port. `step = -1` (R-102).
/// See CountdownLoop.runar.ts for what the missing descending fixture hid.
contract CountdownLoop is SmartContract {
    int immutable target;

    constructor(int _target) {
        target = _target;
    }

    function verify(int seed) public {
        int acc = seed;
        for (int i = 5; i > 1; i--) {
            acc = acc + i;
        }
        require(acc == target);
    }
}

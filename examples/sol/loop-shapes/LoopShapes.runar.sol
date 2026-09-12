pragma runar ^0.1.0;

/// LoopShapes — Solidity-like port. Non-zero loop start plus a countdown loop
/// (R-102: the corpus had neither).
contract LoopShapes is SmartContract {
    int immutable target;

    constructor(int _target) {
        target = _target;
    }

    function verify(int seed) public {
        int acc = seed;
        for (int i = 3; i < 7; i++) {
            acc = acc + i;
        }
        require(acc == target);
    }
}

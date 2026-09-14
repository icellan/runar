pragma runar ^0.1.0;

/// LoopShapes — Solidity-like port. A NON-ZERO loop start, ascending
/// (R-102: the corpus had none).
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

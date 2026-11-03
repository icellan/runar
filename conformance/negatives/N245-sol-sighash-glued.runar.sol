pragma runar ^0.1.0;

// N-244: the sighash marker glued to its flag list on the Solidity surface.
// Only .runar.ts honours the directive; every other surface must refuse ANY
// occurrence of the marker (N-039's rule), not just a word-bounded one, with
// the one shared "not supported by the Solidity surface parser" message.
// Before N-244 every tier read the glued form as prose and compiled ALL|FORKID.
contract Counter is StatefulSmartContract {
    bigint count;

    constructor(bigint _count) {
        count = _count;
    }

    /// @sighashSINGLE|FORKID
    function increment() public {
        this.count++;
    }
}

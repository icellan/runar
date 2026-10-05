// N-153: a .runar.sol empty statement `;`. The TS reference refuses it; the
// Zig tier skipped it. Every tier must refuse it; the TS reference says:
//   Unexpected token in expression: ';'
pragma runar ^0.1.0;

contract N188 is SmartContract {
    bigint immutable t;

    constructor(bigint _t) {
        t = _t;
    }

    function unlock(bigint x) public {
        ;
        require(x == t);
    }
}

// N-491: TS surface-parser operand anchor parity. A parenthesised bigint composite as the left operand of `&&`.
// TS must anchor the refusal on this surface exactly where it does on .runar.ts
// (see n491-operand-anchor-surface-matrix.test.ts).
pragma runar ^0.1.0;

contract Anchor is SmartContract {
    int immutable t;

    constructor(int _t) {
        t = _t;
    }

    function go(int x, bool flag) public {
        require((x + 1) && flag);
    }
}

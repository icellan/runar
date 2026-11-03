// N-489: typecheck diagnostic anchor parity. A bigint identifier as the right operand of `&&`.
// Every tier must anchor the refusal where the TypeScript reference does
// (see n233-diagnostic-anchor-parity.test.ts).
pragma runar ^0.1.0;

contract Anchor is SmartContract {
    int immutable t;

    constructor(int _t) {
        t = _t;
    }

    function go(int x, bool flag) public {
        require(flag && x);
    }
}

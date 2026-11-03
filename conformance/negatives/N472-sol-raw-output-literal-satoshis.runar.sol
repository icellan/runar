// N-472: typecheck diagnostic anchor parity. A boolean literal as the
// addRawOutput satoshis argument, Solidity-like surface.
// Every tier must anchor the refusal where the TypeScript reference does
// (see n233-diagnostic-anchor-parity.test.ts).
pragma runar ^0.1.0;

contract Anchor is StatefulSmartContract {
    bigint count;

    constructor(bigint _count) {
        count = _count;
    }

    function go(ByteString payload) public {
        this.addRawOutput(true, payload);
        this.count = this.count + 1;
        this.addOutput(0, this.count);
    }
}

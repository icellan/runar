pragma runar ^0.1.0;

/// CurrentBlockHeightHelperTernary -- see CurrentBlockHeightHelperTernary.runar.ts.
contract CurrentBlockHeightHelperTernary is StatefulSmartContract {
    bigint immutable start;
    bigint count;

    constructor(bigint _start, bigint _count) {
        start = _start;
        count = _count;
    }

    function height() private returns (bigint) {
        return currentBlockHeight();
    }

    function spend() public {
        require(this.height() >= this.start);
        bigint h = this.count > 5 ? currentBlockHeight() : this.start;
        require(h >= this.start);
        this.count = this.count + 1;
    }
}

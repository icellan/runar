pragma runar ^0.1.0;

/// TernaryExpression -- see TernaryExpression.runar.ts.
contract TernaryExpression is SmartContract {
    int immutable threshold;
    ByteString immutable highTag;
    ByteString immutable lowTag;

    constructor(int _threshold, ByteString _highTag, ByteString _lowTag) {
        threshold = _threshold;
        highTag = _highTag;
        lowTag = _lowTag;
    }

    function check(int x, int distance, ByteString tag, int band) public {
        int d = x > this.threshold ? x - this.threshold : this.threshold - x;
        require(d == distance);

        ByteString t = x > this.threshold ? this.highTag : this.lowTag;
        require(t == tag);

        int b = x > this.threshold ? 2 : (x == this.threshold ? 1 : 0);
        require(b == band);
    }
}

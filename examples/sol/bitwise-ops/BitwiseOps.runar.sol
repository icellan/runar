pragma runar ^0.1.0;

/// @title BitwiseOps
/// @notice Demonstrates bitwise and shift operators on bigint values.
contract BitwiseOps is SmartContract {
    bigint immutable a;
    bigint immutable b;

    constructor(bigint _a, bigint _b) {
        a = _a;
        b = _b;
    }

    /// @notice Check the caller-supplied shift results.
    function testShift(bigint expectedLeft, bigint expectedRight) public {
        bigint left = this.a << 2;
        bigint right = this.a >> 1;
        require(left == expectedLeft);
        require(right == expectedRight);
    }

    /// @notice Check the caller-supplied AND/OR/XOR results; `~` is checked by
    /// double inversion and De Morgan's law (see the TS source for why).
    function testBitwise(bigint expectedAnd, bigint expectedOr, bigint expectedXor) public {
        bigint andResult = this.a & this.b;
        bigint orResult = this.a | this.b;
        bigint xorResult = this.a ^ this.b;
        bigint notResult = ~this.a;
        require(andResult == expectedAnd);
        require(orResult == expectedOr);
        require(xorResult == expectedXor);
        require(~notResult == this.a);
        require(~(this.a | this.b) == (notResult & ~this.b));
    }
}

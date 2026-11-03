pragma runar ^0.1.0;

/// @title ShiftOps
/// @notice Exercises bitshift operators `<<` and `>>` on bigint values.
contract ShiftOps is SmartContract {
    bigint immutable a;

    constructor(bigint _a) {
        a = _a;
    }

    /// @notice Apply left shift and right shift, then check the caller-supplied results.
    function testShift(bigint expectedLeft, bigint expectedRight) public {
        bigint left = this.a << 3;
        bigint right = this.a >> 2;
        require(left == expectedLeft);
        require(right == expectedRight);
    }
}

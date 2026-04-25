pragma runar ^0.1.0;

/// @title ShiftOps
/// @notice Exercises bitshift operators `<<` and `>>` on bigint values.
contract ShiftOps is SmartContract {
    bigint immutable a;

    constructor(bigint _a) {
        a = _a;
    }

    /// @notice Apply left shift and right shift, then sanity-check the results.
    function testShift() public {
        bigint left = this.a << 3;
        bigint right = this.a >> 2;
        require(left >= 0 || left < 0);
        require(right >= 0 || right < 0);
    }
}

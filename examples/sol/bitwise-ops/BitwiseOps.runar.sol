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

    /// @notice Verify shift operators compile and run.
    function testShift() public {
        bigint left = this.a << 2;
        bigint right = this.a >> 1;
        require(left >= 0 || left < 0);
        require(right >= 0 || right < 0);
        require(true);
    }

    /// @notice Verify bitwise operators compile and run.
    function testBitwise() public {
        bigint andResult = this.a & this.b;
        bigint orResult = this.a | this.b;
        bigint xorResult = this.a ^ this.b;
        bigint notResult = ~this.a;
        require(andResult >= 0 || andResult < 0);
        require(orResult >= 0 || orResult < 0);
        require(xorResult >= 0 || xorResult < 0);
        require(notResult >= 0 || notResult < 0);
        require(true);
    }
}

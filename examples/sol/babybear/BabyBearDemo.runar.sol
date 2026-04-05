pragma runar ^0.1.0;

/// @title BabyBearDemo
/// @notice Demonstrates Baby Bear prime field arithmetic.
/// @dev Baby Bear is the prime field used by SP1 STARK proofs (FRI verification).
/// Field prime: p = 2^31 - 2^27 + 1 = 2013265921
///
/// Four operations:
/// - bbFieldAdd(a, b) — (a + b) mod p
/// - bbFieldSub(a, b) — (a - b + p) mod p
/// - bbFieldMul(a, b) — (a * b) mod p
/// - bbFieldInv(a) — a^(p-2) mod p (multiplicative inverse via Fermat)
contract BabyBearDemo is SmartContract {
    constructor() {
    }

    /// @notice Verify field addition.
    /// @param a First operand
    /// @param b Second operand
    /// @param expected Expected result
    function checkAdd(bigint a, bigint b, bigint expected) public {
        require(bbFieldAdd(a, b) == expected);
    }

    /// @notice Verify field subtraction.
    /// @param a First operand
    /// @param b Second operand
    /// @param expected Expected result
    function checkSub(bigint a, bigint b, bigint expected) public {
        require(bbFieldSub(a, b) == expected);
    }

    /// @notice Verify field multiplication.
    /// @param a First operand
    /// @param b Second operand
    /// @param expected Expected result
    function checkMul(bigint a, bigint b, bigint expected) public {
        require(bbFieldMul(a, b) == expected);
    }

    /// @notice Verify field inversion: a * inv(a) === 1.
    /// @param a The value to invert
    function checkInv(bigint a) public {
        bigint inv = bbFieldInv(a);
        require(bbFieldMul(a, inv) == 1);
    }

    /// @notice Verify subtraction is the inverse of addition: (a + b) - b === a.
    /// @param a First operand
    /// @param b Second operand
    function checkAddSubRoundtrip(bigint a, bigint b) public {
        bigint sum = bbFieldAdd(a, b);
        bigint result = bbFieldSub(sum, b);
        require(result == a);
    }

    /// @notice Verify distributive law: a * (b + c) === a*b + a*c.
    /// @param a First operand
    /// @param b Second operand
    /// @param c Third operand
    function checkDistributive(bigint a, bigint b, bigint c) public {
        bigint lhs = bbFieldMul(a, bbFieldAdd(b, c));
        bigint rhs = bbFieldAdd(bbFieldMul(a, b), bbFieldMul(a, c));
        require(lhs == rhs);
    }
}

pragma runar ^0.1.0;

/// @title MathDemo
/// @notice A stateful contract demonstrating every built-in math function
/// available in Rúnar.
/// @dev Bitcoin Script has limited native arithmetic (ADD, SUB, MUL, DIV, MOD).
/// Rúnar provides higher-level math functions that compile into sequences of
/// these primitives, enabling complex financial calculations on-chain.
///
/// Each public method applies one math operation to the contract's stored
/// `value`, showing how these functions compile to pure Bitcoin Script.
/// All operations use integer math — no floating point.
///
/// This contract is intentionally minimal: no signature checks are performed,
/// so any caller can invoke any method. In production, you would combine these
/// math operations with authentication logic.
contract MathDemo is StatefulSmartContract {
    bigint value;

    constructor(bigint _value) {
        value = _value;
    }

    /// @notice Safe division — divides the stored value by `divisor`, asserting
    /// that `divisor` is non-zero. The transaction fails if divisor is 0.
    /// @dev Use cases: splitting payments, computing averages.
    /// @param divisor The non-zero value to divide by
    function divideBy(bigint divisor) public {
        this.value = safediv(this.value, divisor);
    }

    /// @notice Withdraw with a fee calculated in basis points (1 bps = 0.01%).
    /// percentOf(amount, feeBps) computes amount * feeBps / 10000.
    /// Asserts that the total (amount + fee) does not exceed the stored value.
    /// @dev Use cases: fee calculation, royalties, commission deductions.
    /// @param amount The withdrawal amount
    /// @param feeBps The fee in basis points (e.g. 250 = 2.5%)
    function withdrawWithFee(bigint amount, bigint feeBps) public {
        bigint fee = percentOf(amount, feeBps);
        bigint total = amount + fee;
        require(total <= this.value);
        this.value = this.value - total;
    }

    /// @notice Constrains the stored value to the range [lo, hi].
    /// If value < lo, it becomes lo. If value > hi, it becomes hi.
    /// @dev Use cases: enforcing min/max limits on bids, prices, or balances.
    /// @param lo The lower bound (inclusive)
    /// @param hi The upper bound (inclusive)
    function clampValue(bigint lo, bigint hi) public {
        this.value = clamp(this.value, lo, hi);
    }

    /// @notice Replaces the stored value with its sign: -1, 0, or 1.
    /// @dev Use cases: direction detection, comparison results, branch selection.
    function normalize() public {
        this.value = sign(this.value);
    }

    /// @notice Raises the stored value to the power `exp` (integer exponentiation).
    /// @dev Use cases: compound interest, polynomial evaluation.
    /// @param exp The exponent
    function exponentiate(bigint exp) public {
        this.value = pow(this.value, exp);
    }

    /// @notice Replaces the stored value with its integer square root (floor).
    /// @dev Use cases: geometric mean, distance calculations.
    function squareRoot() public {
        this.value = sqrt(this.value);
    }

    /// @notice Replaces the stored value with gcd(value, other) — the greatest
    /// common divisor.
    /// @dev Use cases: fraction simplification, coprimality checks.
    /// @param other The second operand for the GCD computation
    function reduceGcd(bigint other) public {
        this.value = gcd(this.value, other);
    }

    /// @notice Computes (value * numerator) / denominator with intermediate
    /// precision to avoid overflow. Replaces the stored value with the result.
    /// @dev Use cases: currency conversion, proportional allocation, token swaps.
    /// @param numerator The multiplier
    /// @param denominator The divisor (must be non-zero)
    function scaleByRatio(bigint numerator, bigint denominator) public {
        this.value = mulDiv(this.value, numerator, denominator);
    }

    /// @notice Replaces the stored value with floor(log2(value)) — the floor
    /// of the base-2 logarithm.
    /// @dev Use cases: bit-length calculation, binary search depth.
    function computeLog2() public {
        this.value = log2(this.value);
    }
}

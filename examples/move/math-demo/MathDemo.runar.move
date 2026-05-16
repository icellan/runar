// MathDemo — A stateful contract demonstrating every built-in math function
// available in Rúnar.
//
// Bitcoin Script has limited native arithmetic (ADD, SUB, MUL, DIV, MOD).
// Rúnar provides higher-level math functions that compile into sequences of
// these primitives, enabling complex financial calculations on-chain.
//
// Each public method applies one math operation to the contract's stored
// `value`, showing how these functions compile to pure Bitcoin Script.
// All operations use integer math — no floating point.
//
// This contract is intentionally minimal: no signature checks are performed,
// so any caller can invoke any method. In production, you would combine these
// math operations with authentication logic.
module MathDemo {
    resource struct MathDemo {
        value: &mut bigint,
    }

    // Safe division — divides the stored value by `divisor`, asserting that
    // `divisor` is non-zero. The transaction fails if divisor is 0.
    //
    // Use cases: splitting payments, computing averages.
    public fun divide_by(contract: &mut MathDemo, divisor: bigint) {
        contract.value = safediv(contract.value, divisor);
    }

    // Withdraw with a fee calculated in basis points (1 bps = 0.01%).
    // percentOf(amount, fee_bps) computes amount * fee_bps / 10000.
    // Asserts that the total (amount + fee) does not exceed the stored value.
    //
    // Use cases: fee calculation, royalties, commission deductions.
    public fun withdraw_with_fee(contract: &mut MathDemo, amount: bigint, fee_bps: bigint) {
        let fee: bigint = percentOf(amount, fee_bps);
        let total: bigint = amount + fee;
        assert!(total <= contract.value, 0);
        contract.value = contract.value - total;
    }

    // Constrains the stored value to the range [lo, hi].
    // If value < lo, it becomes lo. If value > hi, it becomes hi.
    //
    // Use cases: enforcing min/max limits on bids, prices, or balances.
    public fun clamp_value(contract: &mut MathDemo, lo: bigint, hi: bigint) {
        contract.value = clamp(contract.value, lo, hi);
    }

    // Replaces the stored value with its sign: -1, 0, or 1.
    //
    // Use cases: direction detection, comparison results, branch selection.
    public fun normalize(contract: &mut MathDemo) {
        contract.value = sign(contract.value);
    }

    // Raises the stored value to the power `exp` (integer exponentiation).
    //
    // Use cases: compound interest, polynomial evaluation.
    public fun exponentiate(contract: &mut MathDemo, exp: bigint) {
        contract.value = pow(contract.value, exp);
    }

    // Replaces the stored value with its integer square root (floor).
    //
    // Use cases: geometric mean, distance calculations.
    public fun square_root(contract: &mut MathDemo) {
        contract.value = sqrt(contract.value);
    }

    // Replaces the stored value with gcd(value, other) — the greatest
    // common divisor.
    //
    // Use cases: fraction simplification, coprimality checks.
    public fun reduce_gcd(contract: &mut MathDemo, other: bigint) {
        contract.value = gcd(contract.value, other);
    }

    // Computes (value * numerator) / denominator with intermediate precision
    // to avoid overflow. Replaces the stored value with the result.
    //
    // Use cases: currency conversion, proportional allocation, token swaps.
    public fun scale_by_ratio(contract: &mut MathDemo, numerator: bigint, denominator: bigint) {
        contract.value = mulDiv(contract.value, numerator, denominator);
    }

    // Replaces the stored value with floor(log2(value)) — the floor of the
    // base-2 logarithm.
    //
    // Use cases: bit-length calculation, binary search depth.
    public fun compute_log2(contract: &mut MathDemo) {
        contract.value = log2(contract.value);
    }

    // Replaces the stored value with its absolute value.
    //
    // Use cases: magnitude comparison, distance calculation.
    public fun make_abs(contract: &mut MathDemo) {
        contract.value = abs(contract.value);
    }

    // Replaces the stored value with min(value, other).
    //
    // Use cases: capping bids, picking the smaller of two amounts.
    public fun take_min(contract: &mut MathDemo, other: bigint) {
        contract.value = min(contract.value, other);
    }

    // Replaces the stored value with max(value, other).
    //
    // Use cases: enforcing reserve floors, picking the larger amount.
    public fun take_max(contract: &mut MathDemo, other: bigint) {
        contract.value = max(contract.value, other);
    }

    // Asserts that the stored value lies in the half-open range [lo, hi),
    // mirroring the semantics of Bitcoin Script's OP_WITHIN.
    //
    // Use cases: bounds-checked unlock parameters.
    public fun assert_within(contract: &mut MathDemo, lo: bigint, hi: bigint) {
        assert!(within(contract.value, lo, hi), 0);
    }

    // Safe modulo — replaces the stored value with `value mod divisor`,
    // asserting that `divisor` is non-zero.
    //
    // Use cases: round-robin scheduling, modular index calculation.
    public fun modulo_by(contract: &mut MathDemo, divisor: bigint) {
        contract.value = safemod(contract.value, divisor);
    }

    // Replaces the stored value with the quotient of `value / divisor` via
    // Rúnar's `divmod` builtin (canonical OP_2DUP OP_DIV OP_ROT OP_ROT OP_MOD
    // OP_DROP sequence).
    //
    // Use cases: integer division with a side-effect on the modulo result.
    public fun divmod_by(contract: &mut MathDemo, divisor: bigint) {
        contract.value = divmod(contract.value, divisor);
    }

    // Asserts that the stored value is "truthy" (non-zero) using the
    // dedicated `bool` builtin which compiles to OP_0NOTEQUAL.
    //
    // Use cases: terminal liveness check for non-zero state.
    public fun assert_non_zero(contract: &mut MathDemo) {
        assert!(bool(contract.value), 0);
    }
}

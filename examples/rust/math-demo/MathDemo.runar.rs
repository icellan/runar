use runar::prelude::*;

/// MathDemo — A stateful contract demonstrating every built-in math function
/// available in Rúnar.
///
/// Bitcoin Script has limited native arithmetic (ADD, SUB, MUL, DIV, MOD).
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
#[runar::contract]
pub struct MathDemo {
    pub value: Bigint,
}

#[runar::methods(MathDemo)]
impl MathDemo {
    /// Safe division — divides the stored value by `divisor`, asserting that
    /// `divisor` is non-zero. The transaction fails if divisor is 0.
    ///
    /// Use cases: splitting payments, computing averages.
    #[public]
    pub fn divide_by(&mut self, divisor: Bigint) {
        self.value = safediv(self.value, divisor);
    }

    /// Withdraw with a fee calculated in basis points (1 bps = 0.01%).
    /// `percent_of(amount, fee_bps)` computes `amount * fee_bps / 10000`.
    /// Asserts that the total (amount + fee) does not exceed the stored value.
    ///
    /// Use cases: fee calculation, royalties, commission deductions.
    #[public]
    pub fn withdraw_with_fee(&mut self, amount: Bigint, fee_bps: Bigint) {
        let fee = percent_of(amount, fee_bps);
        let total = amount + fee;
        assert!(total <= self.value);
        self.value = self.value - total;
    }

    /// Constrains the stored value to the range [lo, hi].
    /// If value < lo, it becomes lo. If value > hi, it becomes hi.
    ///
    /// Use cases: enforcing min/max limits on bids, prices, or balances.
    #[public]
    pub fn clamp_value(&mut self, lo: Bigint, hi: Bigint) {
        self.value = clamp(self.value, lo, hi);
    }

    /// Replaces the stored value with its sign: -1, 0, or 1.
    ///
    /// Use cases: direction detection, comparison results, branch selection.
    #[public]
    pub fn normalize(&mut self) {
        self.value = sign(self.value);
    }

    /// Raises the stored value to the power `exp` (integer exponentiation).
    ///
    /// Use cases: compound interest, polynomial evaluation.
    #[public]
    pub fn exponentiate(&mut self, exp: Bigint) {
        self.value = pow(self.value, exp);
    }

    /// Replaces the stored value with its integer square root (floor).
    ///
    /// Use cases: geometric mean, distance calculations.
    #[public]
    pub fn square_root(&mut self) {
        self.value = sqrt(self.value);
    }

    /// Replaces the stored value with gcd(value, other) — the greatest
    /// common divisor.
    ///
    /// Use cases: fraction simplification, coprimality checks.
    #[public]
    pub fn reduce_gcd(&mut self, other: Bigint) {
        self.value = gcd(self.value, other);
    }

    /// Computes `(value * numerator) / denominator` with intermediate precision
    /// to avoid overflow. Replaces the stored value with the result.
    ///
    /// Use cases: currency conversion, proportional allocation, token swaps.
    #[public]
    pub fn scale_by_ratio(&mut self, numerator: Bigint, denominator: Bigint) {
        self.value = mul_div(self.value, numerator, denominator);
    }

    /// Replaces the stored value with floor(log2(value)) — the floor of the
    /// base-2 logarithm.
    ///
    /// Use cases: bit-length calculation, binary search depth.
    #[public]
    pub fn compute_log2(&mut self) {
        self.value = log2(self.value);
    }
}

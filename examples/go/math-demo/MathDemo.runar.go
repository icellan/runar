package contract

import runar "github.com/icellan/runar/packages/runar-go"

// MathDemo is a stateful contract demonstrating every built-in math function
// available in Rúnar.
//
// Bitcoin Script has limited native arithmetic (ADD, SUB, MUL, DIV, MOD).
// Rúnar provides higher-level math functions that compile into sequences of
// these primitives, enabling complex financial calculations on-chain.
//
// Each public method applies one math operation to the contract's stored
// Value, showing how these functions compile to pure Bitcoin Script.
// All operations use integer math — no floating point.
//
// This contract is intentionally minimal: no signature checks are performed,
// so any caller can invoke any method. In production, you would combine these
// math operations with authentication logic.
type MathDemo struct {
	runar.StatefulSmartContract
	Value runar.Bigint
}

// DivideBy performs safe division — divides the stored value by divisor,
// asserting that divisor is non-zero. The transaction fails if divisor is 0.
//
// Use cases: splitting payments, computing averages.
func (c *MathDemo) DivideBy(divisor runar.Bigint) {
	c.Value = runar.Safediv(c.Value, divisor)
}

// WithdrawWithFee withdraws with a fee calculated in basis points
// (1 bps = 0.01%). PercentOf(amount, feeBps) computes
// amount * feeBps / 10000. Asserts that the total (amount + fee) does not
// exceed the stored value.
//
// Use cases: fee calculation, royalties, commission deductions.
func (c *MathDemo) WithdrawWithFee(amount, feeBps runar.Bigint) {
	fee := runar.PercentOf(amount, feeBps)
	total := amount + fee
	runar.Assert(total <= c.Value)
	c.Value = c.Value - total
}

// ClampValue constrains the stored value to the range [lo, hi].
// If value < lo, it becomes lo. If value > hi, it becomes hi.
//
// Use cases: enforcing min/max limits on bids, prices, or balances.
func (c *MathDemo) ClampValue(lo, hi runar.Bigint) {
	c.Value = runar.Clamp(c.Value, lo, hi)
}

// Normalize replaces the stored value with its sign: -1, 0, or 1.
//
// Use cases: direction detection, comparison results, branch selection.
func (c *MathDemo) Normalize() {
	c.Value = runar.Sign(c.Value)
}

// Exponentiate raises the stored value to the power exp (integer
// exponentiation).
//
// Use cases: compound interest, polynomial evaluation.
func (c *MathDemo) Exponentiate(exp runar.Bigint) {
	c.Value = runar.Pow(c.Value, exp)
}

// SquareRoot replaces the stored value with its integer square root (floor).
//
// Use cases: geometric mean, distance calculations.
func (c *MathDemo) SquareRoot() {
	c.Value = runar.Sqrt(c.Value)
}

// ReduceGcd replaces the stored value with gcd(value, other) — the greatest
// common divisor.
//
// Use cases: fraction simplification, coprimality checks.
func (c *MathDemo) ReduceGcd(other runar.Bigint) {
	c.Value = runar.Gcd(c.Value, other)
}

// ScaleByRatio computes (value * numerator) / denominator with intermediate
// precision to avoid overflow. Replaces the stored value with the result.
//
// Use cases: currency conversion, proportional allocation, token swaps.
func (c *MathDemo) ScaleByRatio(numerator, denominator runar.Bigint) {
	c.Value = runar.MulDiv(c.Value, numerator, denominator)
}

// ComputeLog2 replaces the stored value with floor(log2(value)) — the floor
// of the base-2 logarithm.
//
// Use cases: bit-length calculation, binary search depth.
func (c *MathDemo) ComputeLog2() {
	c.Value = runar.Log2(c.Value)
}

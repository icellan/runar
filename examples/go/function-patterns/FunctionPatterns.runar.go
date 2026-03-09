// FunctionPatterns demonstrates every way functions and methods can be
// used inside a Rúnar Go contract.
//
// Rúnar contracts support four categories of callable code:
//
//   1. Public methods      — exported methods on the contract struct.
//                            These are the spending entry points that
//                            appear in the compiled Bitcoin Script.
//
//   2. Private methods     — unexported methods on the contract struct.
//                            These can access contract state via the
//                            receiver (c.Field) and are inlined by the
//                            compiler at call sites.
//
//   3. Standalone helpers  — unexported package-level functions (no
//                            receiver). Pure logic that cannot access
//                            contract state. Useful for math utilities
//                            and reusable computations.
//
//   4. Built-in functions  — functions from the runar package (e.g.
//                            runar.Assert, runar.Hash160, runar.Safediv).
//                            These map directly to Bitcoin Script opcodes.
//
// The receiver name can be anything (c, s, self, contract, etc.) — the
// compiler reads it from the method signature.

package contract

import runar "github.com/icellan/runar/packages/runar-go"

// ---------------------------------------------------------------------------
// Contract struct
// ---------------------------------------------------------------------------

// FunctionPatterns is a stateful contract that tracks a balance and an
// owner, demonstrating all the function call patterns available in Rúnar Go.
type FunctionPatterns struct {
	runar.StatefulSmartContract
	Owner   runar.PubKey `runar:"readonly"` // immutable: contract creator
	Balance runar.Bigint                   // stateful: current balance
}

// ---------------------------------------------------------------------------
// 1. Public methods — spending entry points
// ---------------------------------------------------------------------------
// Exported (capitalized) methods become public spending paths in the
// compiled locking script. Each is a separate OP_IF branch that the
// spending transaction selects via a method index.
//
// Public methods must not return a value.

// Deposit adds funds. Demonstrates calling a private method and a
// standalone helper from a public method.
func (c *FunctionPatterns) Deposit(sig runar.Sig, amount runar.Bigint) {
	// Built-in: signature verification
	c.requireOwner(sig)

	// Built-in: assertion with a standalone helper
	runar.Assert(isPositive(amount))

	// Update state
	c.Balance = c.Balance + amount
}

// Withdraw removes funds after applying a fee. Demonstrates chaining
// multiple private methods and built-in math functions.
func (c *FunctionPatterns) Withdraw(sig runar.Sig, amount runar.Bigint, feeBps runar.Bigint) {
	c.requireOwner(sig)
	runar.Assert(amount > 0)

	// Private method: compute fee
	fee := c.computeFee(amount, feeBps)
	total := amount + fee

	// Built-in: assert sufficient balance
	runar.Assert(total <= c.Balance)

	c.Balance = c.Balance - total
}

// Scale multiplies the balance by a rational number (num/denom).
// Demonstrates standalone helpers for pure math.
func (c *FunctionPatterns) Scale(sig runar.Sig, numerator runar.Bigint, denominator runar.Bigint) {
	c.requireOwner(sig)

	// Standalone helper: safe ratio scaling
	c.Balance = scaleValue(c.Balance, numerator, denominator)
}

// Normalize clamps the balance to a range and rounds down to the nearest
// step size. Demonstrates composing multiple standalone helpers.
func (c *FunctionPatterns) Normalize(sig runar.Sig, lo runar.Bigint, hi runar.Bigint, step runar.Bigint) {
	c.requireOwner(sig)

	// Standalone helpers composed together
	clamped := clampValue(c.Balance, lo, hi)
	c.Balance = roundDown(clamped, step)
}

// ---------------------------------------------------------------------------
// 2. Private methods — unexported methods with receiver
// ---------------------------------------------------------------------------
// Unexported (lowercase) methods on the contract struct are private.
// They can read and write contract state via the receiver, and are
// inlined at call sites by the compiler (no separate script function).
//
// Private methods may return a value.

// requireOwner verifies the signature matches the contract owner.
// This is a common pattern: extract repeated assertion logic into a
// private method so multiple public methods can share it.
func (c *FunctionPatterns) requireOwner(sig runar.Sig) {
	runar.Assert(runar.CheckSig(sig, c.Owner))
}

// computeFee calculates a fee in basis points on an amount.
// Returns the fee value. Demonstrates a private method with a return value
// that accesses no state (but could if needed).
func (c *FunctionPatterns) computeFee(amount runar.Bigint, feeBps runar.Bigint) runar.Bigint {
	return runar.PercentOf(amount, feeBps)
}

// ---------------------------------------------------------------------------
// 3. Standalone helper functions — no receiver
// ---------------------------------------------------------------------------
// Unexported package-level functions have no receiver and cannot access
// contract state (no c.Field). They are pure functions: input goes in
// via parameters, output comes back via return value.
//
// Use these for reusable math utilities, validation logic, or any
// computation that doesn't need contract fields.

// isPositive returns true if n > 0.
// Demonstrates the simplest standalone helper: a boolean predicate.
func isPositive(n runar.Bigint) bool {
	return n > 0
}

// scaleValue computes (value * numerator) / denominator safely.
// Demonstrates a standalone helper using a built-in math function.
func scaleValue(value runar.Bigint, numerator runar.Bigint, denominator runar.Bigint) runar.Bigint {
	return runar.MulDiv(value, numerator, denominator)
}

// clampValue constrains a value to the range [lo, hi].
// Demonstrates wrapping a built-in for readability.
func clampValue(value runar.Bigint, lo runar.Bigint, hi runar.Bigint) runar.Bigint {
	return runar.Clamp(value, lo, hi)
}

// roundDown rounds a value down to the nearest multiple of step.
// Demonstrates a standalone helper with arithmetic: value - (value % step).
func roundDown(value runar.Bigint, step runar.Bigint) runar.Bigint {
	remainder := runar.Safemod(value, step)
	return value - remainder
}

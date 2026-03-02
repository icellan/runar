// FunctionPatterns demonstrates every way functions and methods can be
// used inside a Rúnar Rust contract.
//
// Rúnar contracts support three categories of callable code:
//
//   1. Public methods      — annotated with #[public]. These are the
//                            spending entry points that appear in the
//                            compiled Bitcoin Script.
//
//   2. Private methods     — methods without #[public]. These can access
//                            contract state via &self / &mut self and are
//                            inlined by the compiler at call sites.
//                            Private methods may return a value.
//
//   3. Built-in functions  — functions from runar::prelude (e.g. check_sig,
//                            safediv, percent_of, clamp). These map
//                            directly to Bitcoin Script opcodes.
//
// Note: standalone functions outside the impl block are not supported
// by the Rúnar Rust parser. All helpers must be methods on the struct.

use runar::prelude::*;

#[runar::contract]
pub struct FunctionPatterns {
    #[readonly]
    pub owner: PubKey,   // immutable: contract creator
    pub balance: Bigint, // stateful: current balance
}

#[runar::methods(FunctionPatterns)]
impl FunctionPatterns {
    // -------------------------------------------------------------------
    // 1. Public methods — spending entry points
    // -------------------------------------------------------------------
    // #[public] methods become separate OP_IF branches in the compiled
    // locking script.
    //
    // Public methods take &mut self and must not return a value.

    /// Deposit adds funds. Calls a private method and a built-in.
    #[public]
    pub fn deposit(&mut self, sig: &Sig, amount: Bigint) {
        // Private method: shared signature check
        self.require_owner(sig);

        // Built-in: assertion
        assert!(amount > 0);

        // Update state
        self.balance += amount;
    }

    /// Withdraw removes funds after applying a fee.
    /// Demonstrates a private method that returns a value.
    #[public]
    pub fn withdraw(&mut self, sig: &Sig, amount: Bigint, fee_bps: Bigint) {
        self.require_owner(sig);
        assert!(amount > 0);

        // Private method with return value
        let fee = self.compute_fee(amount, fee_bps);
        let total = amount + fee;

        assert!(total <= self.balance);
        self.balance -= total;
    }

    /// Scale multiplies the balance by a rational number.
    /// Demonstrates a private method wrapping a built-in.
    #[public]
    pub fn scale(&mut self, sig: &Sig, numerator: Bigint, denominator: Bigint) {
        self.require_owner(sig);
        self.balance = self.scale_value(self.balance, numerator, denominator);
    }

    /// Normalize clamps the balance to a range and rounds down.
    /// Demonstrates composing multiple private helper methods.
    #[public]
    pub fn normalize(&mut self, sig: &Sig, lo: Bigint, hi: Bigint, step: Bigint) {
        self.require_owner(sig);
        let clamped = self.clamp_value(self.balance, lo, hi);
        self.balance = self.round_down(clamped, step);
    }

    // -------------------------------------------------------------------
    // 2. Private methods — inlined helpers
    // -------------------------------------------------------------------
    // Methods without #[public] are private. They can read/write contract
    // state via &self / &mut self and may return a value.

    /// Verify the caller is the contract owner.
    fn require_owner(&self, sig: &Sig) {
        assert!(check_sig(sig, &self.owner));
    }

    /// Compute a fee in basis points. Returns the fee amount.
    fn compute_fee(&self, amount: Bigint, fee_bps: Bigint) -> Bigint {
        percent_of(amount, fee_bps)
    }

    /// Multiply a value by a fraction using mul_div for precision.
    fn scale_value(&self, value: Bigint, numerator: Bigint, denominator: Bigint) -> Bigint {
        mul_div(value, numerator, denominator)
    }

    /// Clamp a value to [lo, hi].
    fn clamp_value(&self, value: Bigint, lo: Bigint, hi: Bigint) -> Bigint {
        clamp(value, lo, hi)
    }

    /// Round down to the nearest multiple of step.
    fn round_down(&self, value: Bigint, step: Bigint) -> Bigint {
        let remainder = safemod(value, step);
        value - remainder
    }
}

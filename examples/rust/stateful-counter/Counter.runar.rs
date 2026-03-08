use runar::prelude::*;

/// Counter — the simplest possible stateful smart contract.
///
/// Demonstrates Rúnar's state management: a counter that persists its value
/// across spending transactions on the Bitcoin SV blockchain.
///
/// Because this struct uses `#[runar::contract]` (without `#[readonly]` on
/// `count`), the compiler automatically injects:
///   - `checkPreimage` at each public method entry — verifies the spending
///     transaction matches the sighash preimage.
///   - State continuation at each public method exit — serializes updated
///     state into the new output script.
///
/// **Script layout (on-chain):**
/// ```text
/// Locking: <contract logic> OP_RETURN <count>
/// ```
/// The state (`count`) is serialized as push data after `OP_RETURN`. When
/// spent, the compiler-injected preimage check ensures the new output carries
/// the correct updated state.
///
/// **No authorization checks.** This contract is intentionally minimal for
/// educational purposes — anyone can call increment or decrement. A real
/// stateful contract would include signature verification or other access
/// control.
#[runar::contract]
pub struct Counter {
    // No #[readonly] = mutable (stateful, persists across transactions)
    pub count: Bigint,
}

#[runar::methods(Counter)]
impl Counter {
    /// Increments count by 1. Anyone can call this method.
    #[public]
    pub fn increment(&mut self) {
        self.count += 1;
    }

    /// Decrements count by 1.
    /// Asserts count > 0 to prevent underflow. Anyone can call this method.
    #[public]
    pub fn decrement(&mut self) {
        assert!(self.count > 0);
        self.count -= 1;
    }
}

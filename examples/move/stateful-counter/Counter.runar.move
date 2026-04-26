// Counter — the simplest possible stateful smart contract.
//
// Demonstrates Rúnar's state management: a counter that persists its value
// across spending transactions on the Bitcoin SV blockchain.
//
// Because Counter is declared as a `resource struct`, the compiler
// automatically injects:
//   - checkPreimage at each public function entry — verifies the spending
//     transaction matches the sighash preimage.
//   - State continuation at each public function exit — serializes updated
//     state into the new output script.
//
// Script layout (on-chain):
//   Locking: <contract logic> OP_RETURN <count>
//
// The state (count) is serialized as push data after OP_RETURN. When spent,
// the compiler-injected preimage check ensures the new output carries the
// correct updated state.
//
// No authorization checks. This contract is intentionally minimal for
// educational purposes — anyone can call increment or decrement. A real
// stateful contract would include signature verification or other access
// control.
module Counter {
    resource struct Counter {
        count: &mut bigint, // mutable (stateful, persists across transactions)
    }

    // Increments count by 1. Anyone can call this function.
    public fun increment(contract: &mut Counter) {
        contract.count = contract.count + 1;
    }

    // Decrements count by 1.
    // Asserts count > 0 to prevent underflow. Anyone can call this function.
    public fun decrement(contract: &mut Counter) {
        assert!(contract.count > 0, 0);
        contract.count = contract.count - 1;
    }
}

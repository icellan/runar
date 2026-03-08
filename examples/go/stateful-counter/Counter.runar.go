package contract

import runar "github.com/icellan/runar/packages/runar-go"

// Counter — the simplest possible stateful smart contract.
//
// Demonstrates Rúnar's state management: a counter that persists its value
// across spending transactions on the Bitcoin SV blockchain.
//
// Because this struct embeds runar.StatefulSmartContract, the compiler
// automatically injects:
//   - checkPreimage at each public method entry — verifies the spending
//     transaction matches the sighash preimage.
//   - State continuation at each public method exit — serializes updated
//     state into the new output script.
//
// Script layout (on-chain):
//
//	Locking: <contract logic> OP_RETURN <count>
//
// The state (Count) is serialized as push data after OP_RETURN. When spent,
// the compiler-injected preimage check ensures the new output carries the
// correct updated state.
//
// No authorization checks. This contract is intentionally minimal for
// educational purposes — anyone can call Increment or Decrement. A real
// stateful contract would include signature verification or other access
// control.
type Counter struct {
	runar.StatefulSmartContract
	Count runar.Bigint // no tag = mutable (stateful, persists across transactions)
}

// Increment increments Count by 1. Anyone can call this method.
func (c *Counter) Increment() {
	c.Count++
}

// Decrement decrements Count by 1.
// Asserts Count > 0 to prevent underflow. Anyone can call this method.
func (c *Counter) Decrement() {
	runar.Assert(c.Count > 0)
	c.Count--
}

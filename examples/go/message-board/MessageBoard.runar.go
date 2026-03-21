package contract

import runar "github.com/icellan/runar/packages/runar-go"

// MessageBoard -- a stateful smart contract with a ByteString mutable state field.
//
// Demonstrates Runar's ByteString state management: a message that persists
// and can be updated across spending transactions on the Bitcoin SV blockchain.
//
// Because this struct embeds runar.StatefulSmartContract, the compiler
// automatically injects:
//   - checkPreimage at each public method entry -- verifies the spending
//     transaction matches the sighash preimage.
//   - State continuation at each public method exit -- serializes updated
//     state into the new output script.
//
// Script layout (on-chain):
//
//	Locking: <contract logic> OP_RETURN <message> <owner>
//
// The state (Message) is serialized as push data after OP_RETURN. The
// Owner is readonly and baked into the locking script.
//
// Authorization: Post has no access control -- anyone can update the
// message. Burn requires the owner's signature to permanently destroy
// the contract (no continuation output).
type MessageBoard struct {
	runar.StatefulSmartContract
	Message runar.ByteString              // no tag = mutable (stateful, persists across transactions)
	Owner   runar.PubKey `runar:"readonly"` // readonly -- baked into the locking script
}

// Post replaces the current message with a new one. Anyone can call this method.
func (c *MessageBoard) Post(newMessage runar.ByteString) {
	c.Message = newMessage
}

// Burn permanently destroys the contract -- terminal spend with no continuation output.
// Only the owner can burn the contract (requires a valid signature).
func (c *MessageBoard) Burn(sig runar.Sig) {
	runar.Assert(runar.CheckSig(sig, c.Owner))
}

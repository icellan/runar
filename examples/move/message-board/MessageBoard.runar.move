// MessageBoard -- a stateful smart contract with a ByteString mutable state field.
//
// Demonstrates Runar's ByteString state management: a message that persists
// and can be updated across spending transactions on the Bitcoin SV blockchain.
//
// Because MessageBoard is declared as a `resource struct`, the compiler
// automatically injects:
//   - checkPreimage at each public function entry -- verifies the spending
//     transaction matches the sighash preimage.
//   - State continuation at each public function exit -- serializes updated
//     state into the new output script.
//
// Script layout (on-chain):
//   Locking: <contract logic> OP_RETURN <message> <owner>
//
// The state (message) is serialized as push data after OP_RETURN. The
// owner is readonly and baked into the locking script.
//
// Authorization: post has no access control -- anyone can update the
// message. burn requires the owner's signature to permanently destroy
// the contract (no continuation output).
module MessageBoard {
    use runar::types::{PubKey, Sig, ByteString};
    use runar::crypto::{check_sig};

    resource struct MessageBoard {
        message: ByteString,   // mutable (stateful, persists across transactions)
        owner: PubKey,         // readonly -- baked into the locking script
    }

    // Post a new message, replacing the current one. Anyone can call.
    public fun post(contract: &mut MessageBoard, new_message: ByteString) {
        contract.message = new_message;
    }

    // Burn the contract -- terminal spend with no continuation output.
    // Only the owner can burn the contract (requires a valid signature).
    public fun burn(contract: &MessageBoard, sig: Sig) {
        assert!(check_sig(sig, contract.owner), 0);
    }
}

use runar::prelude::*;

/// MessageBoard -- a stateful smart contract with a ByteString mutable state field.
///
/// Demonstrates Runar's ByteString state management: a message that persists
/// and can be updated across spending transactions on the Bitcoin SV blockchain.
///
/// Because this struct uses `#[runar::contract]`, the compiler automatically
/// injects:
///   - `checkPreimage` at each public method entry -- verifies the spending
///     transaction matches the sighash preimage.
///   - State continuation at each public method exit -- serializes updated
///     state into the new output script.
///
/// **Script layout (on-chain):**
/// ```text
/// Locking: <contract logic> OP_RETURN <message> <owner>
/// ```
/// The state (`message`) is serialized as push data after `OP_RETURN`. The
/// `owner` is readonly and baked into the locking script.
///
/// **Authorization:** `post` has no access control -- anyone can update the
/// message. `burn` requires the owner's signature to permanently destroy
/// the contract (no continuation output).
#[runar::contract]
pub struct MessageBoard {
    /// The current message. Mutable -- updated via `post`.
    pub message: ByteString,
    /// The contract owner's public key. Readonly -- baked into the locking script.
    #[readonly]
    pub owner: PubKey,
}

#[runar::methods(MessageBoard)]
impl MessageBoard {
    /// Post a new message, replacing the current one. Anyone can call.
    #[public]
    pub fn post(&mut self, new_message: ByteString) {
        self.message = new_message;
    }

    /// Burn the contract -- terminal spend with no continuation output.
    /// Only the owner can burn the contract (requires a valid signature).
    #[public]
    pub fn burn(&self, sig: &Sig) {
        assert!(check_sig(sig, &self.owner));
    }
}

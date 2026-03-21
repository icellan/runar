pragma runar ^0.1.0;

/// @title MessageBoard
/// @notice A stateful smart contract with a ByteString mutable state field.
/// @dev Demonstrates Runar's ByteString state management: a message that
/// persists and can be updated across spending transactions on the Bitcoin SV
/// blockchain.
///
/// Because this contract inherits StatefulSmartContract, the compiler
/// automatically injects:
///   - `checkPreimage` at each public function entry -- verifies the spending
///     transaction matches the sighash preimage.
///   - State continuation at each public function exit -- serializes updated
///     state into the new output script.
///
/// Script layout (on-chain):
///   Locking: <contract logic> OP_RETURN <message> <owner>
///
/// The state (`message`) is serialized as push data after OP_RETURN. The
/// `owner` is readonly and baked into the locking script.
///
/// Authorization: `post` has no access control -- anyone can update the
/// message. `burn` requires the owner's signature to permanently destroy
/// the contract (no continuation output).
contract MessageBoard is StatefulSmartContract {
    ByteString message;         // mutable (stateful, persists across transactions)
    PubKey immutable owner;     // readonly -- baked into the locking script

    constructor(ByteString _message, PubKey _owner) {
        message = _message;
        owner = _owner;
    }

    /// @notice Post a new message, replacing the current one. Anyone can call.
    function post(ByteString newMessage) public {
        this.message = newMessage;
    }

    /// @notice Burn the contract -- terminal spend with no continuation output.
    /// @dev Only the owner can burn the contract (requires a valid signature).
    function burn(Sig sig) public {
        require(checkSig(sig, this.owner));
    }
}

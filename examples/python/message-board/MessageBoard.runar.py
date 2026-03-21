from runar import (
    StatefulSmartContract, PubKey, Sig, ByteString, Readonly,
    public, assert_, check_sig,
)


class MessageBoard(StatefulSmartContract):
    """MessageBoard -- a stateful smart contract with a ByteString mutable state field.

    Demonstrates Runar's ByteString state management: a message that persists
    and can be updated across spending transactions on the Bitcoin SV blockchain.

    Because this class extends StatefulSmartContract, the compiler automatically
    injects:
      - checkPreimage at each public method entry -- verifies the spending
        transaction matches the sighash preimage.
      - State continuation at each public method exit -- serializes updated
        state into the new output script.

    Script layout (on-chain)::

        Locking: <contract logic> OP_RETURN <message> <owner>

    The state (message) is serialized as push data after OP_RETURN. The
    owner is readonly and baked into the locking script.

    Authorization: post has no access control -- anyone can update the
    message. burn requires the owner's signature to permanently destroy
    the contract (no continuation output).

    Args:
        message: The current message stored on-chain (mutable ByteString).
        owner:   The contract owner's compressed public key (readonly).
    """

    message: ByteString            # mutable (stateful, persists across transactions)
    owner: Readonly[PubKey]        # readonly -- baked into the locking script

    def __init__(self, message: ByteString, owner: PubKey):
        super().__init__(message, owner)
        self.message = message
        self.owner = owner

    @public
    def post(self, new_message: ByteString):
        """Post a new message, replacing the current one. Anyone can call."""
        self.message = new_message

    @public
    def burn(self, sig: Sig):
        """Burn the contract -- terminal spend with no continuation output.

        Only the owner can burn the contract (requires a valid signature).

        Args:
            sig: Owner's ECDSA signature.
        """
        assert_(check_sig(sig, self.owner))

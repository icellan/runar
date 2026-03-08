"""CovenantVault -- a stateless Bitcoin covenant contract.

A covenant is a self-enforcing spending constraint: the locking script
dictates not just *who* can spend the funds, but *how* they may be spent.
This contract demonstrates the pattern by combining three verification
layers in its single public method:

  1. Owner authorization  -- the owner's ECDSA signature must be valid
     (proves who is spending).
  2. Preimage verification -- check_preimage (OP_PUSH_TX) proves the
     contract is inspecting the real spending transaction, enabling
     on-chain introspection of its fields.
  3. Covenant rule -- the output amount must be >= min_amount, which
     constrains the transaction structure itself.

Script layout (simplified)::

    Unlocking: <sig> <amount> <txPreimage>
    Locking:   <pubKey> OP_CHECKSIG OP_VERIFY <checkPreimage>
               <amount >= minAmount> OP_VERIFY

Use cases for this pattern include withdrawal limits, time-locked vaults,
rate-limited spending, and enforced change addresses.

Contract model: Stateless (SmartContract). All constructor parameters
are readonly and baked into the locking script at deploy time.
"""

from runar import (
    SmartContract, PubKey, Sig, Addr, SigHashPreimage, Bigint,
    public, assert_, check_sig, check_preimage,
)

class CovenantVault(SmartContract):
    """Bitcoin covenant vault with minimum-output enforcement.

    Args:
        owner:      Owner's compressed ECDSA public key (33 bytes).
        recipient:  Recipient address (20-byte hash160 of pubkey).
        min_amount: Minimum output amount in satoshis enforced by the
                    covenant rule.
    """

    owner: PubKey
    recipient: Addr
    min_amount: Bigint

    def __init__(self, owner: PubKey, recipient: Addr, min_amount: Bigint):
        super().__init__(owner, recipient, min_amount)
        self.owner = owner
        self.recipient = recipient
        self.min_amount = min_amount

    @public
    def spend(self, sig: Sig, amount: Bigint, tx_preimage: SigHashPreimage):
        """Spend funds held by this covenant.

        Args:
            sig:         ECDSA signature from the owner (~72 bytes DER).
            amount:      Declared output amount; must be >= min_amount.
            tx_preimage: Sighash preimage (variable length) used by
                         check_preimage to verify the spending transaction.
        """
        # Layer 1: Owner authorization -- verify the ECDSA signature.
        assert_(check_sig(sig, self.owner))
        # Layer 2: Preimage verification -- proves on-chain introspection.
        assert_(check_preimage(tx_preimage))
        # Layer 3: Covenant rule -- enforce minimum output amount.
        assert_(amount >= self.min_amount)

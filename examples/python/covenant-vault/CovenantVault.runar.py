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
  3. Covenant rule -- the contract constructs the expected P2PKH output
     on-chain (recipient address + min_amount satoshis) and verifies its
     hash against the transaction's hashOutputs field. This constrains
     both the destination and the amount at the consensus level.

Script layout (simplified)::

    Unlocking: <opPushTxSig> <sig> <txPreimage>
    Locking:   <pubKey> OP_CHECKSIG OP_VERIFY <checkPreimage>
               <buildP2PKH(recipient)> <num2bin(minAmount,8)> OP_CAT
               OP_HASH256 <extractOutputHash(preimage)> OP_EQUAL OP_VERIFY

Use cases for this pattern include withdrawal limits, time-locked vaults,
rate-limited spending, and enforced change addresses.

Contract model: Stateless (SmartContract). All constructor parameters
are readonly and baked into the locking script at deploy time.
"""

from runar import (
    SmartContract, PubKey, Sig, Addr, ByteString, SigHashPreimage, Bigint,
    public, assert_, check_sig, check_preimage, extract_output_hash, hash256, num2bin, cat,
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
    def spend(self, sig: Sig, tx_preimage: SigHashPreimage):
        """Spend funds held by this covenant.

        Constructs the expected P2PKH output on-chain and verifies it against
        the transaction's hashOutputs from the sighash preimage.

        Args:
            sig:         ECDSA signature from the owner (~72 bytes DER).
            tx_preimage: Sighash preimage for check_preimage verification.
        """
        assert_(check_sig(sig, self.owner))
        assert_(check_preimage(tx_preimage))

        # Construct expected P2PKH output and verify against hashOutputs
        p2pkh_script = cat(cat('1976a914', self.recipient), '88ac')
        expected_output = cat(num2bin(self.min_amount, 8), p2pkh_script)
        assert_(hash256(expected_output) == extract_output_hash(tx_preimage))

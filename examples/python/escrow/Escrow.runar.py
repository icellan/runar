from runar import SmartContract, PubKey, Sig, public, assert_, check_sig


class Escrow(SmartContract):
    """Three-party escrow contract for marketplace payment protection.

    Holds funds in a UTXO until two parties jointly authorize a spend. The buyer
    deposits funds by sending to this contract's locking script. Two spending
    paths allow funds to move depending on the transaction outcome:

    - release -- seller + arbiter both sign to release funds to the seller
      (e.g., goods delivered successfully).
    - refund  -- buyer + arbiter both sign to refund funds to the buyer
      (e.g., dispute resolved in buyer's favor).

    The arbiter serves as the trust anchor -- no single party can act alone.
    Both paths require two signatures (dual-sig), ensuring the arbiter must
    co-sign every spend. This prevents unilateral action by either party.

    Script layout::

        Unlocking: <methodIndex> <sig1> <sig2>
        Locking:   OP_IF <seller checkSig> <arbiter checkSig>
                   OP_ELSE <buyer checkSig> <arbiter checkSig> OP_ENDIF

    Args:
        buyer:   Buyer's compressed public key (33 bytes).
        seller:  Seller's compressed public key (33 bytes).
        arbiter: Arbiter's compressed public key (33 bytes).
    """

    buyer: PubKey
    seller: PubKey
    arbiter: PubKey

    def __init__(self, buyer: PubKey, seller: PubKey, arbiter: PubKey):
        super().__init__(buyer, seller, arbiter)
        self.buyer = buyer
        self.seller = seller
        self.arbiter = arbiter

    @public
    def release(self, seller_sig: Sig, arbiter_sig: Sig):
        """Release escrowed funds to the seller.

        Requires both the seller's and arbiter's signatures.

        Args:
            seller_sig: Seller's signature.
            arbiter_sig: Arbiter's signature.
        """
        assert_(check_sig(seller_sig, self.seller))
        assert_(check_sig(arbiter_sig, self.arbiter))

    @public
    def refund(self, buyer_sig: Sig, arbiter_sig: Sig):
        """Refund escrowed funds to the buyer.

        Requires both the buyer's and arbiter's signatures.

        Args:
            buyer_sig: Buyer's signature.
            arbiter_sig: Arbiter's signature.
        """
        assert_(check_sig(buyer_sig, self.buyer))
        assert_(check_sig(arbiter_sig, self.arbiter))

from runar import SmartContract, PubKey, Sig, public, assert_, check_sig


class Escrow(SmartContract):
    """Three-party escrow contract for marketplace payment protection.

    Holds funds in a UTXO until the buyer, seller, or arbiter authorizes
    release. The buyer deposits funds by sending to this contract's locking
    script. Four spending paths allow either party to move funds depending on
    the transaction outcome:

    - release_by_seller  -- seller confirms delivery, releases funds to themselves.
    - release_by_arbiter -- arbiter resolves a dispute in the seller's favor.
    - refund_to_buyer    -- buyer cancels before delivery (self-authorized).
    - refund_by_arbiter  -- arbiter resolves a dispute in the buyer's favor.

    This is a stateless contract (SmartContract). The three public keys are
    readonly constructor parameters baked into the locking script at deploy time.

    Script layout::

        Unlocking: <methodIndex> <sig>
        Locking:   OP_IF <release paths> OP_ELSE <refund paths> OP_ENDIF

    Each public method becomes an OP_IF branch selected by the method index in
    the unlocking script.

    Design note: Each path requires only one signature. A production escrow
    might use 2-of-3 multisig for stronger guarantees, but this contract
    demonstrates the multi-method spending pattern clearly.

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
    def release_by_seller(self, sig: Sig):
        """Seller confirms delivery and releases the escrowed funds.

        Args:
            sig: Seller's signature (~72 bytes).
        """
        assert_(check_sig(sig, self.seller))

    @public
    def release_by_arbiter(self, sig: Sig):
        """Arbiter resolves a dispute in the seller's favor, releasing funds.

        Args:
            sig: Arbiter's signature (~72 bytes).
        """
        assert_(check_sig(sig, self.arbiter))

    @public
    def refund_to_buyer(self, sig: Sig):
        """Buyer cancels the transaction before delivery and reclaims funds.

        Args:
            sig: Buyer's signature (~72 bytes).
        """
        assert_(check_sig(sig, self.buyer))

    @public
    def refund_by_arbiter(self, sig: Sig):
        """Arbiter resolves a dispute in the buyer's favor, refunding funds.

        Args:
            sig: Arbiter's signature (~72 bytes).
        """
        assert_(check_sig(sig, self.arbiter))

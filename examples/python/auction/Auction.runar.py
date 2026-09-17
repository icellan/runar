from runar import (
    StatefulSmartContract, PubKey, Sig, Bigint, Readonly,
    public, assert_, check_sig, extract_locktime, extract_sequence,
)


class Auction(StatefulSmartContract):
    """On-chain English auction contract.

    Bidders compete by submitting progressively higher bids until a block-height
    deadline. After the deadline, only the auctioneer can close the auction.

    Lifecycle:
        1. The auctioneer deploys the contract with themselves as the initial
           highest bidder, a highest bid of 0, and a block-height deadline.
        2. Anyone calls :meth:`bid` to outbid the current leader. Each successful
           bid creates a new UTXO carrying the updated state. Bidding stays open
           for as long as that UTXO is unspent -- see Time enforcement below.
        3. Once the deadline has passed, the auctioneer calls :meth:`close` to
           finalize the auction and spend the UTXO.

    Stateful mechanics:
        Extends :class:`StatefulSmartContract`. The compiler auto-injects
        ``checkPreimage`` at method entry and a state-continuation output at
        method exit for state-mutating methods. Each continuation UTXO encodes
        state as::

            OP_RETURN <auctioneer> <highest_bidder> <highest_bid> <deadline>

    Time enforcement -- read this before copying the pattern:
        nLockTime is chosen by the SPENDER and enforced by consensus as a
        NOT-BEFORE: the transaction becomes mineable once the chain has reached
        it. Nothing about it bounds the chain from above. A script can therefore
        assert "not before T" and can NEVER assert "before T" -- a bidder at
        height T+1 simply stamps a stale nLockTime of T-1 and the node mines it.

        So :meth:`bid` carries no deadline check at all: bidding is open until
        the auctioneer closes. :meth:`close` uses the direction that does work,
        ``nLockTime >= deadline``, paired with
        ``extract_sequence != 0xffffffff``. That second assert is load-bearing,
        not decoration: consensus ignores nLockTime entirely when every input is
        final, so without it the auctioneer could stamp ``nLockTime = deadline``
        on an all-final transaction and close at any height, before anyone had a
        chance to bid.

        A trustless "bids only before T" window needs a time source the contract
        can read as state -- an oracle or a tick -- not the spending
        transaction's own locktime. v1 does not ship one.
    """

    auctioneer: Readonly[PubKey]      # Auction creator's public key. Immutable — baked into script.
    highest_bidder: PubKey             # Current highest bidder. Mutable state across transactions.
    highest_bid: Bigint                # Current highest bid in satoshis. Mutable state.
    deadline: Readonly[Bigint]         # Block height cutoff. Immutable.

    def __init__(self, auctioneer: PubKey, highest_bidder: PubKey,
                 highest_bid: Bigint, deadline: Bigint):
        super().__init__(auctioneer, highest_bidder, highest_bid, deadline)
        self.auctioneer = auctioneer
        self.highest_bidder = highest_bidder
        self.highest_bid = highest_bid
        self.deadline = deadline

    @public
    def bid(self, sig: Sig, bidder: PubKey, bid_amount: Bigint):
        """Submit a new bid that outbids the current highest.

        State-mutating: the compiler auto-injects ``checkPreimage`` at entry and
        appends a state-continuation output at exit, creating a new UTXO with
        the updated ``highest_bidder`` and ``highest_bid``.

        Args:
            sig: Bidder's signature proving they authorized this bid.
            bidder: Public key of the new bidder.
            bid_amount: Bid in satoshis; must exceed the current highest bid.

        There is deliberately no deadline check here -- see Time enforcement on
        the class. A bid lands whenever the contract's UTXO is still unspent.
        """
        # Verify the bidder authorized this bid (prevents griefing)
        assert_(check_sig(sig, bidder))
        # Reject bids that do not exceed the current highest
        assert_(bid_amount > self.highest_bid)
        # Persist new leader into on-chain state
        self.highest_bidder = bidder
        self.highest_bid = bid_amount

    @public
    def close(self, sig: Sig):
        """Close the auction after the deadline has passed.

        Non-mutating: the compiler auto-injects ``checkPreimage`` but does NOT
        append a state-continuation output, so the UTXO is fully spent (no
        successor). Only the auctioneer may call this.

        Args:
            sig: Signature from the auctioneer proving ownership.
        """
        # Verify the caller is the auctioneer
        assert_(check_sig(sig, self.auctioneer))
        # Enforce that the deadline has passed: nLockTime must be >= deadline
        assert_(extract_locktime(self.tx_preimage) >= self.deadline)
        # ...and that consensus actually enforces that nLockTime. A transaction
        # whose inputs are all final (nSequence 0xffffffff) is mineable at any height
        # with nLockTime ignored, so without this the assert above is script-only
        # theatre and the auctioneer can close immediately.
        assert_(extract_sequence(self.tx_preimage) != 4294967295)

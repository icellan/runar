from runar import (
    SmartContract, PubKey, Sig, ByteString, RabinSig, RabinPubKey, Bigint,
    public, assert_, check_sig, verify_rabin_sig, num2bin,
)


class OraclePriceFeed(SmartContract):
    """A stateless oracle contract for price-triggered payouts.

    Demonstrates the "oracle pattern" where off-chain data (e.g., asset prices)
    is cryptographically signed by a trusted oracle and verified on-chain using
    Rabin signatures. Rabin signatures are well-suited for Bitcoin Script because
    verification requires only modular multiplication and comparison -- operations
    that are cheap in Script.

    The contract enforces three verification layers:
        1. Oracle verification -- the price was genuinely signed by the trusted oracle's Rabin key
        2. Price threshold -- the price must exceed 50,000 (application-specific business logic)
        3. Receiver authorization -- the receiver must provide a valid ECDSA signature

    Use cases: derivatives/futures settlement, price-triggered payouts, conditional
    escrow based on market data, insurance contracts.

    Contract model: Stateless (SmartContract). The oracle's Rabin public key and the
    receiver's ECDSA public key are immutable constructor parameters.

    Attributes:
        oracle_pub_key: Rabin public key of the trusted oracle (a large integer
            modulus, typically 128+ bytes).
        receiver: ECDSA compressed public key (33 bytes) of the authorized
            payout receiver.
    """

    oracle_pub_key: RabinPubKey
    receiver: PubKey

    def __init__(self, oracle_pub_key: RabinPubKey, receiver: PubKey):
        super().__init__(oracle_pub_key, receiver)
        self.oracle_pub_key = oracle_pub_key
        self.receiver = receiver

    @public
    def settle(self, price: Bigint, rabin_sig: RabinSig, padding: ByteString, sig: Sig):
        """Settle the contract by proving a price was signed by the oracle and exceeds
        the threshold. The receiver must also sign to authorize the payout.

        Args:
            price: The oracle-attested price value (integer).
            rabin_sig: Rabin signature produced by the oracle over the price (variable length).
            padding: Rabin signature padding bytes required for verification (variable length).
            sig: ECDSA signature (~72 bytes) from the receiver authorizing the spend.
        """
        # Layer 1: Oracle verification -- convert the price to its 8-byte little-endian
        # canonical form (the format the oracle signs), then verify the Rabin signature
        # against the oracle's public key using modular arithmetic.
        msg = num2bin(price, 8)
        assert_(verify_rabin_sig(msg, rabin_sig, padding, self.oracle_pub_key))
        # Layer 2: Price threshold -- application-specific business logic requiring
        # the oracle-attested price to exceed 50,000 before the payout is allowed.
        assert_(price > 50000)
        # Layer 3: Receiver authorization -- the designated receiver must provide a
        # valid ECDSA signature to claim the payout, preventing front-running.
        assert_(check_sig(sig, self.receiver))

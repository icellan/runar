from runar import (
    SmartContract, PubKey, Sig, ByteString, RabinSig, RabinPubKey, Bigint,
    public, assert_, check_sig, verify_rabin_sig, num2bin,
)

class OraclePriceFeed(SmartContract):
    oracle_pub_key: RabinPubKey
    receiver: PubKey

    def __init__(self, oracle_pub_key: RabinPubKey, receiver: PubKey):
        super().__init__(oracle_pub_key, receiver)
        self.oracle_pub_key = oracle_pub_key
        self.receiver = receiver

    @public
    def settle(self, price: Bigint, rabin_sig: RabinSig, padding: ByteString, sig: Sig):
        # Verify oracle signed this price
        msg = num2bin(price, 8)
        assert_(verify_rabin_sig(msg, rabin_sig, padding, self.oracle_pub_key))

        # Price must be above threshold for payout
        assert_(price > 50000)

        # Receiver must sign
        assert_(check_sig(sig, self.receiver))

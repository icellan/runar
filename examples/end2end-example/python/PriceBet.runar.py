"""PriceBet -- a two-party price wager settled by a Rabin oracle.

Oracle replay note: The oracle signs only num2bin(price, 8) -- raw price
bytes with no domain separation. Any valid oracle signature for a given
price can be reused across all PriceBet contracts that share the same
oracle_pub_key. This is acceptable when oracle attestations represent
reusable global facts (e.g., "BTC price at block N"). For production
contracts requiring per-instance isolation, include domain fields such as
a contract ID, UTXO outpoint, or expiry timestamp in the signed message.

Mirrors the reference variants in:
- examples/end2end-example/ts/PriceBet.runar.ts
- examples/end2end-example/go/PriceBet.runar.go
- examples/end2end-example/rust/src/price_bet.runar.rs
- examples/end2end-example/ruby/PriceBet.runar.rb
"""

from runar import (
    SmartContract, PubKey, Sig, ByteString, RabinSig, RabinPubKey, Bigint,
    public, assert_, check_sig, verify_rabin_sig, num2bin,
)


class PriceBet(SmartContract):
    alice_pub_key: PubKey
    bob_pub_key: PubKey
    oracle_pub_key: RabinPubKey
    strike_price: Bigint

    def __init__(
        self,
        alice_pub_key: PubKey,
        bob_pub_key: PubKey,
        oracle_pub_key: RabinPubKey,
        strike_price: Bigint,
    ):
        super().__init__(alice_pub_key, bob_pub_key, oracle_pub_key, strike_price)
        self.alice_pub_key = alice_pub_key
        self.bob_pub_key = bob_pub_key
        self.oracle_pub_key = oracle_pub_key
        self.strike_price = strike_price

    @public
    def settle(
        self,
        price: Bigint,
        rabin_sig: RabinSig,
        padding: ByteString,
        alice_sig: Sig,
        bob_sig: Sig,
    ):
        msg = num2bin(price, 8)
        assert_(verify_rabin_sig(msg, rabin_sig, padding, self.oracle_pub_key))
        assert_(price > 0)
        if price > self.strike_price:
            # bob_sig is present in the unlocking script for stack alignment but
            # is intentionally not checked in this branch -- alice is the winner.
            assert_(check_sig(alice_sig, self.alice_pub_key))
        else:
            # alice_sig is present in the unlocking script for stack alignment
            # but is intentionally not checked in this branch -- bob is the winner.
            assert_(check_sig(bob_sig, self.bob_pub_key))

    @public
    def cancel(self, alice_sig: Sig, bob_sig: Sig):
        assert_(check_sig(alice_sig, self.alice_pub_key))
        assert_(check_sig(bob_sig, self.bob_pub_key))

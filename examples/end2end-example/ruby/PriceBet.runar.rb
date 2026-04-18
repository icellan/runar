require 'runar'

# PriceBet -- a two-party price wager settled by a Rabin oracle.
#
# Oracle replay note: The oracle signs only num2bin(price, 8) -- raw price
# bytes with no domain separation. Any valid oracle signature for a given
# price can be reused across all PriceBet contracts that share the same
# oracle_pub_key. This is acceptable when oracle attestations represent
# reusable global facts (e.g., "BTC price at block N"). For production
# contracts requiring per-instance isolation, include domain fields such as
# a contract ID, UTXO outpoint, or expiry timestamp in the signed message.
class PriceBet < Runar::SmartContract
  prop :alice_pub_key, PubKey
  prop :bob_pub_key, PubKey
  prop :oracle_pub_key, RabinPubKey
  prop :strike_price, Bigint

  def initialize(alice_pub_key, bob_pub_key, oracle_pub_key, strike_price)
    super(alice_pub_key, bob_pub_key, oracle_pub_key, strike_price)
    @alice_pub_key = alice_pub_key
    @bob_pub_key = bob_pub_key
    @oracle_pub_key = oracle_pub_key
    @strike_price = strike_price
  end

  runar_public price: Bigint, rabin_sig: RabinSig, padding: ByteString, alice_sig: Sig, bob_sig: Sig
  def settle(price, rabin_sig, padding, alice_sig, bob_sig)
    msg = num2bin(price, 8)
    assert verify_rabin_sig(msg, rabin_sig, padding, @oracle_pub_key)

    assert price > 0

    if price > @strike_price
      # bob_sig is present in the unlocking script for stack alignment but is
      # intentionally not checked in this branch -- only alice (the winner) signs.
      assert check_sig(alice_sig, @alice_pub_key)
    else
      # alice_sig is present in the unlocking script for stack alignment but is
      # intentionally not checked in this branch -- only bob (the winner) signs.
      assert check_sig(bob_sig, @bob_pub_key)
    end
  end

  runar_public alice_sig: Sig, bob_sig: Sig
  def cancel(alice_sig, bob_sig)
    assert check_sig(alice_sig, @alice_pub_key)
    assert check_sig(bob_sig, @bob_pub_key)
  end
end

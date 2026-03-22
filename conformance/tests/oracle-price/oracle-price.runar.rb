require 'runar'

class OraclePriceFeed < Runar::SmartContract
  prop :oracle_pub_key, RabinPubKey
  prop :receiver, PubKey

  def initialize(oracle_pub_key, receiver)
    super(oracle_pub_key, receiver)
    @oracle_pub_key = oracle_pub_key
    @receiver = receiver
  end

  runar_public price: Bigint, rabin_sig: RabinSig, padding: ByteString, sig: Sig
  def settle(price, rabin_sig, padding, sig)
    msg = num2bin(price, 8)
    assert verify_rabin_sig(msg, rabin_sig, padding, @oracle_pub_key)
    assert price > 50_000
    assert check_sig(sig, @receiver)
  end
end

# F-286: verifyRabinSig's modulus (4th argument) is a spending-method parameter,
# so the spender picks n and forges any message (n = 1, sig = 0 passes real
# Spend). Every tier must refuse:
#   verifyRabinSig public key (4th argument) must be a contract property or a literal; a spender-supplied Rabin modulus lets anyone forge a signature
# Shape: Ruby surface, runar_public method parameter.
require 'runar'

class RabinParam < Runar::SmartContract
  prop :pk, RabinPubKey

  def initialize(pk)
    super(pk)
    @pk = pk
  end

  runar_public msg: ByteString, sig: RabinSig, padding: ByteString, n: RabinPubKey
  def settle(msg, sig, padding, n)
    assert verify_rabin_sig(msg, sig, padding, n)
  end
end

require 'runar'

class MultiSigVerifyFused < Runar::SmartContract
  prop :pk1, PubKey
  prop :pk2, PubKey
  prop :pk3, PubKey

  def initialize(pk1, pk2, pk3)
    super(pk1, pk2, pk3)
    @pk1 = pk1
    @pk2 = pk2
    @pk3 = pk3
  end

  runar_public sig1: Sig, sig2: Sig, amount: Bigint
  def unlock(sig1, sig2, amount)
    assert check_multi_sig([sig1, sig2], [@pk1, @pk2, @pk3])
    assert amount > 0
  end
end

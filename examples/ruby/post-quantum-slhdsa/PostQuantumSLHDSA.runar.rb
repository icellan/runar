require 'runar'

class PostQuantumSLHDSA < Runar::SmartContract
  prop :pubkey, ByteString

  def initialize(pubkey)
    super(pubkey)
    @pubkey = pubkey
  end

  runar_public msg: ByteString, sig: ByteString
  def spend(msg, sig)
    assert verify_slh_dsa_sha2_128s(msg, sig, @pubkey)
  end
end

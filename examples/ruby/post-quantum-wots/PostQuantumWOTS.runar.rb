require 'runar'

class PostQuantumWOTS < Runar::SmartContract
  prop :pubkey, ByteString

  def initialize(pubkey)
    super(pubkey)
    @pubkey = pubkey
  end

  runar_public msg: ByteString, sig: ByteString
  def spend(msg, sig)
    assert verify_wots(msg, sig, @pubkey)
  end
end

require 'runar'

class PostQuantumWallet < Runar::SmartContract
  prop :ecdsa_pub_key_hash, Addr
  prop :wots_pub_key_hash, ByteString

  def initialize(ecdsa_pub_key_hash, wots_pub_key_hash)
    super(ecdsa_pub_key_hash, wots_pub_key_hash)
    @ecdsa_pub_key_hash = ecdsa_pub_key_hash
    @wots_pub_key_hash = wots_pub_key_hash
  end

  runar_public wots_sig: ByteString, wots_pub_key: ByteString, sig: Sig, pub_key: PubKey
  def spend(wots_sig, wots_pub_key, sig, pub_key)
    assert hash160(pub_key) == @ecdsa_pub_key_hash
    assert check_sig(sig, pub_key)
    assert hash160(wots_pub_key) == @wots_pub_key_hash
    assert verify_wots(sig, wots_sig, wots_pub_key)
  end
end

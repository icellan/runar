require 'runar'

class P384Wallet < Runar::SmartContract
  prop :ecdsa_pub_key_hash, Addr
  prop :p384_pub_key_hash, ByteString

  def initialize(ecdsa_pub_key_hash, p384_pub_key_hash)
    super(ecdsa_pub_key_hash, p384_pub_key_hash)
    @ecdsa_pub_key_hash = ecdsa_pub_key_hash
    @p384_pub_key_hash = p384_pub_key_hash
  end

  runar_public p384_sig: ByteString, p384_pub_key: ByteString, sig: Sig, pub_key: PubKey
  def spend(p384_sig, p384_pub_key, sig, pub_key)
    assert hash160(pub_key) == @ecdsa_pub_key_hash
    assert check_sig(sig, pub_key)
    assert hash160(p384_pub_key) == @p384_pub_key_hash
    assert verify_ecdsa_p384(sig, p384_sig, p384_pub_key)
  end
end

require 'runar'

class P256Wallet < Runar::SmartContract
  prop :ecdsa_pub_key_hash, Addr
  prop :p256_pub_key_hash, ByteString

  def initialize(ecdsa_pub_key_hash, p256_pub_key_hash)
    super(ecdsa_pub_key_hash, p256_pub_key_hash)
    @ecdsa_pub_key_hash = ecdsa_pub_key_hash
    @p256_pub_key_hash = p256_pub_key_hash
  end

  runar_public p256_sig: ByteString, p256_pub_key: ByteString, sig: Sig, pub_key: PubKey
  def spend(p256_sig, p256_pub_key, sig, pub_key)
    assert hash160(pub_key) == @ecdsa_pub_key_hash
    assert check_sig(sig, pub_key)
    assert hash160(p256_pub_key) == @p256_pub_key_hash
    assert verify_ecdsa_p256(sig, p256_sig, p256_pub_key)
  end
end

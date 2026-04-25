require 'runar'

class SPHINCSWallet < Runar::SmartContract
  prop :ecdsa_pub_key_hash, Addr
  prop :slhdsa_pub_key_hash, ByteString

  def initialize(ecdsa_pub_key_hash, slhdsa_pub_key_hash)
    super(ecdsa_pub_key_hash, slhdsa_pub_key_hash)
    @ecdsa_pub_key_hash = ecdsa_pub_key_hash
    @slhdsa_pub_key_hash = slhdsa_pub_key_hash
  end

  runar_public slhdsa_sig: ByteString, slhdsa_pub_key: ByteString, sig: Sig, pub_key: PubKey
  def spend(slhdsa_sig, slhdsa_pub_key, sig, pub_key)
    # Step 1: Verify ECDSA -- proves sig commits to this transaction
    assert hash160(pub_key) == @ecdsa_pub_key_hash
    assert check_sig(sig, pub_key)

    # Step 2: Verify SLH-DSA -- proves ECDSA sig was authorized by SLH-DSA key holder
    assert hash160(slhdsa_pub_key) == @slhdsa_pub_key_hash
    assert verify_slh_dsa_sha2_128s(sig, slhdsa_sig, slhdsa_pub_key)
  end
end

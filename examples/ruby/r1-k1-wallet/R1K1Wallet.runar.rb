# frozen_string_literal: true

require 'runar'

class R1K1Wallet < Runar::SmartContract
  prop :r1_salted_pub_key_hash, Addr
  prop :k1_pub_key_hash, Addr

  def initialize(r1_salted_pub_key_hash, k1_pub_key_hash)
    super(r1_salted_pub_key_hash, k1_pub_key_hash)
    @r1_salted_pub_key_hash = r1_salted_pub_key_hash
    @k1_pub_key_hash = k1_pub_key_hash
  end

  runar_public r1_sig: ByteString, r1_pub_key: ByteString, r1_salt: ByteString, tx_preimage: SigHashPreimage
  def spend_r1(r1_sig, r1_pub_key, r1_salt, tx_preimage)
    assert len(r1_salt) == 32
    assert hash160(cat(r1_pub_key, r1_salt)) == @r1_salted_pub_key_hash
    assert substr(tx_preimage, len(tx_preimage) - 4, 4) == '41000000'
    assert check_preimage(tx_preimage)
    assert verify_ecdsa_p256(sha256(tx_preimage), r1_sig, r1_pub_key)
  end

  runar_public k1_sig: Sig, k1_pub_key: PubKey
  def recover_k1(k1_sig, k1_pub_key)
    assert hash160(k1_pub_key) == @k1_pub_key_hash
    assert check_sig(k1_sig, k1_pub_key)
  end
end

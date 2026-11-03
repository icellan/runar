require 'runar'

class HexToBytesInitializer < Runar::SmartContract
  prop :p2pkh_prefix, ByteString, default: '1976a914'
  prop :p2pkh_suffix, ByteString, default: '88ac'
  prop :pub_key_hash, Addr

  def initialize(pub_key_hash)
    super(pub_key_hash)
    @pub_key_hash = pub_key_hash
  end

  runar_public sig: Sig, pub_key: PubKey, script: ByteString
  def unlock(sig, pub_key, script)
    assert hash160(pub_key) == @pub_key_hash
    assert cat(cat(@p2pkh_prefix, @pub_key_hash), @p2pkh_suffix) == script
    assert check_sig(sig, pub_key)
  end
end

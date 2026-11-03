# N-301: a misspelt `prop` option (`embed_alwyas` for `embed_always`) on the
# Ruby surface. Every tier used to drop it silently and compile the contract
# WITHOUT the embed-always behaviour the author asked for; every tier must now
# refuse it with the one shared "unknown prop option" diagnostic.
require 'runar'

class Meta < Runar::SmartContract
  prop :pub_key_hash, Addr
  prop :metadata_id, ByteString, embed_alwyas: true

  def initialize(pub_key_hash, metadata_id)
    super(pub_key_hash, metadata_id)
    @pub_key_hash = pub_key_hash
    @metadata_id = metadata_id
  end

  runar_public sig: Sig, pub_key: PubKey
  def unlock(sig, pub_key)
    assert hash160(pub_key) == @pub_key_hash
    assert check_sig(sig, pub_key)
  end
end

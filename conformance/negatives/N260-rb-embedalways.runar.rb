# N-268: an `embedAlways` marker on a readonly field on the Ruby surface.
# Only .runar.ts honours the directive; every other surface must refuse it
# with the one shared "not supported by the Ruby surface parser" message
# (mirrors N-244's sighash fix — before N-268 the Zig, Ruby and Java tiers
# each used their own, differently worded text here).
# With the marker replaced by prose, metadata_id is an ordinary unreferenced
# readonly field: every tier eliminates it by DCE, so this compiles to the
# same P2PKH-shaped script everywhere.
require 'runar'

class Meta < Runar::SmartContract
  prop :pub_key_hash, Addr
  # @embedAlways
  prop :metadata_id, ByteString

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

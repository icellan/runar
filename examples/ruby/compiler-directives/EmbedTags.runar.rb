# EmbedTags -- Ruby port of
# examples/ts/compiler-directives/EmbedTags.runar.ts.
#
# embed_always: true on a FixedArray prop applies to every expanded slot: all
# three are kept although unlock reads only @tags[1].

require 'runar'

class EmbedTags < Runar::SmartContract
  prop :pub_key_hash, Addr
  prop :tags, FixedArray[Bigint, 3], readonly: true, embed_always: true, default: [7, 9, 11]

  def initialize(pub_key_hash)
    super(pub_key_hash)
    @pub_key_hash = pub_key_hash
  end

  runar_public sig: Sig, pub_key: PubKey, amount: Bigint
  def unlock(sig, pub_key, amount)
    assert amount >= @tags[1]
    assert hash160(pub_key) == @pub_key_hash
    assert check_sig(sig, pub_key)
  end
end

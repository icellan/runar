# N-319: the class has no closing `end` (the file stops after the last method's
# `end`). Every tier must refuse it with the one shared "missing closing 'end'"
# diagnostic instead of parsing a partial class silently.
require 'runar'

class Unterminated < Runar::SmartContract
  prop :pub_key_hash, Addr

  def initialize(pub_key_hash)
    super(pub_key_hash)
    @pub_key_hash = pub_key_hash
  end

  runar_public sig: Sig, pub_key: PubKey
  def unlock(sig, pub_key)
    assert hash160(pub_key) == @pub_key_hash
    assert check_sig(sig, pub_key)
  end

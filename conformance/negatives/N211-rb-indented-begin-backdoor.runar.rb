# N-004: the .runar.rb parser skipped a class-body token it did not recognise
# and ignored everything after the class's `end`, so an indented `=begin`
# (which Ruby lexes as `=` then `begin`) let a "commented-out" method become
# the only spend path while the guarded one was dropped. Every tier must
# refuse with:
#   Unexpected token in class body: '='
# Shape: an indented =begin / =end around a drain backdoor; its `end` closes the class.
require 'runar'

class P2PKH < Runar::SmartContract
  prop :pub_key_hash, Addr

  def initialize(pub_key_hash)
    super(pub_key_hash)
    @pub_key_hash = pub_key_hash
  end

  =begin
  Old debugging entry point, disabled:
  runar_public sig: Sig, pk: PubKey
  def drain(sig, pk)
    assert true
  end
end
  =end

  runar_public sig: Sig, pub_key: PubKey
  def unlock(sig, pub_key)
    assert hash160(pub_key) == @pub_key_hash
    assert check_sig(sig, pub_key)
  end
end

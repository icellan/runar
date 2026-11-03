# N-004: the .runar.rb parser skipped a class-body token it did not recognise
# and ignored everything after the class's `end`, so an indented `=begin`
# (which Ruby lexes as `=` then `begin`) let a "commented-out" method become
# the only spend path while the guarded one was dropped. Every tier must
# refuse with:
#   Unexpected token after class end: 'def'
# Shape: a method defined after the class's `end`.
require 'runar'

class P2PKH < Runar::SmartContract
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
end
def drain(sig)
  assert true
end

# N-021: an unterminated `=begin` embedded document in .runar.rb. Before
# N-021 the TS reference, Rust, Python, Zig and Java lexed the block as code:
# the commented-out `drain` compiled as the only spend path and the real
# `unlock` was dropped (517777, anyone-can-spend). Every tier must refuse with:
#   unterminated '=begin' block comment starting at line 17: missing '=end'
require 'runar'

class P2PKH < Runar::SmartContract
  prop :pub_key_hash, Addr

  def initialize(pub_key_hash)
    super(pub_key_hash)
    @pub_key_hash = pub_key_hash
  end

  # The block below is never closed.
=begin
  Old debugging entry point, disabled:
  runar_public sig: Sig, pk: PubKey
  def drain(sig, pk)
    assert true
  end
end

  runar_public sig: Sig, pub_key: PubKey
  def unlock(sig, pub_key)
    assert hash160(pub_key) == @pub_key_hash
    assert check_sig(sig, pub_key)
  end
end

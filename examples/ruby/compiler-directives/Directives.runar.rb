# Directives -- Ruby port of
# examples/ts/compiler-directives/Directives.runar.ts.
#
# The two compiler directives in their native Ruby spelling (N-093): the prop
# option embed_always: true keeps deploy_tag in the locking script although no
# method reads it, and the class macro runar_sighash declares the BIP-143 mode
# the next method, spend_single, commits to.

require 'runar'

class Directives < Runar::SmartContract
  prop :pub_key_hash, Addr
  prop :deploy_tag, ByteString, embed_always: true

  def initialize(pub_key_hash, deploy_tag)
    super(pub_key_hash, deploy_tag)
    @pub_key_hash = pub_key_hash
    @deploy_tag = deploy_tag
  end

  runar_public sig: Sig, pub_key: PubKey
  def spend_all(sig, pub_key)
    assert hash160(pub_key) == @pub_key_hash
    assert check_sig(sig, pub_key)
  end

  runar_sighash 'SINGLE|FORKID'
  runar_public sig: Sig, pub_key: PubKey
  def spend_single(sig, pub_key)
    assert hash160(pub_key) == @pub_key_hash
    assert check_sig(sig, pub_key)
  end
end

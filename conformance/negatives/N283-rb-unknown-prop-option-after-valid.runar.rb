# N-301: an unknown `prop` option that FOLLOWS a valid one (`readonly: true,
# colour: 1`). The valid option must not shield the unknown one; every tier
# must refuse with the one shared "unknown prop option" diagnostic.
require 'runar'

class Meta < Runar::SmartContract
  prop :pub_key_hash, Addr, readonly: true, colour: 1

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

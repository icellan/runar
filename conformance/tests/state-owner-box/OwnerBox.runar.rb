require 'runar'

# OwnerBox -- F-352 second witness for the mutable-state shape {PubKey}.
class OwnerBox < Runar::StatefulSmartContract
  prop :owner, PubKey

  def initialize(owner)
    super(owner)
    @owner = owner
  end

  runar_public sig: Sig, new_owner: PubKey
  def rotate(sig, new_owner)
    assert check_sig(sig, @owner)
    @owner = new_owner
  end
end

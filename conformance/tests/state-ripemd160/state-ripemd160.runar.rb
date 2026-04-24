require 'runar'

class HashRegistry < Runar::StatefulSmartContract
  prop :current_hash, Ripemd160

  def initialize(current_hash)
    super(current_hash)
    @current_hash = current_hash
  end

  runar_public new_hash: Ripemd160
  def update(new_hash)
    @current_hash = new_hash
    assert true
  end
end

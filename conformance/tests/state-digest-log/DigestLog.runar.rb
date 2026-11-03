require 'runar'

# DigestLog -- F-352 second witness for the mutable-state shape {Ripemd160}.
class DigestLog < Runar::StatefulSmartContract
  prop :digest, Ripemd160

  def initialize(digest)
    super(digest)
    @digest = digest
  end

  runar_public new_digest: Ripemd160, version: Bigint
  def replace(new_digest, version)
    assert version > 0
    @digest = new_digest
  end
end

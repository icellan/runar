require 'runar'

# Notary -- F-352 second witness for the mutable-state shape
# {ByteString, PubKey, bigint}, with the PubKey declared first.
class Notary < Runar::StatefulSmartContract
  prop :signer, PubKey
  prop :note, ByteString
  prop :seq, Bigint

  def initialize(signer, note, seq)
    super(signer, note, seq)
    @signer = signer
    @note = note
    @seq = seq
  end

  runar_public sig: Sig, next_note: ByteString
  def notarize(sig, next_note)
    assert check_sig(sig, @signer)
    @note = next_note
    @seq = @seq + 1
  end
end

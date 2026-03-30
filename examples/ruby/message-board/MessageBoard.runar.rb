require 'runar'

class MessageBoard < Runar::StatefulSmartContract
  prop :message, ByteString
  prop :owner, PubKey, readonly: true

  def initialize(message, owner)
    super(message, owner)
    @message = message
    @owner = owner
  end

  # Post a new message, replacing the current one.
  # Anyone can call this method -- no signature required.
  runar_public new_message: ByteString
  def post(new_message)
    @message = new_message
  end

  # Burn the contract -- terminal spend with no continuation output.
  # Only the owner can burn the contract (requires a valid signature).
  runar_public sig: Sig
  def burn(sig)
    assert check_sig(sig, @owner)
  end
end

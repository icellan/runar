require 'runar'

class MessageBoard < Runar::StatefulSmartContract
  prop :message, ByteString
  prop :owner, PubKey, readonly: true

  def initialize(message, owner)
    super(message, owner)
    @message = message
    @owner = owner
  end

  runar_public new_message: ByteString
  def post(new_message)
    @message = new_message
    assert true
  end

  runar_public sig: Sig
  def burn(sig)
    assert check_sig(sig, @owner)
  end
end

require 'runar'

class SimpleNFT < Runar::StatefulSmartContract
  prop :owner, PubKey
  prop :token_id, ByteString, readonly: true
  prop :metadata, ByteString, readonly: true

  def initialize(owner, token_id, metadata)
    super(owner, token_id, metadata)
    @owner = owner
    @token_id = token_id
    @metadata = metadata
  end

  runar_public sig: Sig, new_owner: PubKey, output_satoshis: Bigint
  def transfer(sig, new_owner, output_satoshis)
    assert check_sig(sig, @owner)
    assert output_satoshis >= 1
    add_output(output_satoshis, new_owner)
  end

  runar_public sig: Sig
  def burn(sig)
    assert check_sig(sig, @owner)
  end
end

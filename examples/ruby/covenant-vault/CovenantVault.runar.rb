require 'runar'

class CovenantVault < Runar::SmartContract
  prop :owner, PubKey
  prop :recipient, Addr
  prop :min_amount, Bigint

  def initialize(owner, recipient, min_amount)
    super(owner, recipient, min_amount)
    @owner = owner
    @recipient = recipient
    @min_amount = min_amount
  end

  runar_public sig: Sig, tx_preimage: SigHashPreimage
  def spend(sig, tx_preimage)
    assert check_sig(sig, @owner)
    assert check_preimage(tx_preimage)
    p2pkh_script = cat(cat('1976a914', @recipient), '88ac')
    expected_output = cat(num2bin(@min_amount, 8), p2pkh_script)
    assert hash256(expected_output) == extract_output_hash(tx_preimage)
  end
end

require 'runar'

class FungibleToken < Runar::StatefulSmartContract
  prop :owner, PubKey
  prop :balance, Bigint
  prop :merge_balance, Bigint
  prop :token_id, ByteString, readonly: true

  def initialize(owner, balance, merge_balance, token_id)
    super(owner, balance, merge_balance, token_id)
    @owner = owner
    @balance = balance
    @merge_balance = merge_balance
    @token_id = token_id
  end

  runar_public sig: Sig, to: PubKey, amount: Bigint, output_satoshis: Bigint
  def transfer(sig, to, amount, output_satoshis)
    assert check_sig(sig, @owner)
    assert output_satoshis >= 1
    total_balance = @balance + @merge_balance
    assert amount > 0
    assert amount <= total_balance
    add_output(output_satoshis, to, amount, 0)
    if amount < total_balance
      add_output(output_satoshis, @owner, total_balance - amount, 0)
    end
  end

  runar_public sig: Sig, to: PubKey, output_satoshis: Bigint
  def send(sig, to, output_satoshis)
    assert check_sig(sig, @owner)
    assert output_satoshis >= 1
    add_output(output_satoshis, to, @balance + @merge_balance, 0)
  end

  runar_public sig: Sig, other_balance: Bigint, all_prevouts: ByteString, output_satoshis: Bigint
  def merge(sig, other_balance, all_prevouts, output_satoshis)
    assert check_sig(sig, @owner)
    assert output_satoshis >= 1
    assert other_balance >= 0
    assert hash256(all_prevouts) == extract_hash_prevouts(@tx_preimage)
    my_outpoint = extract_outpoint(@tx_preimage)
    first_outpoint = substr(all_prevouts, 0, 36)
    my_balance = @balance + @merge_balance
    if my_outpoint == first_outpoint
      add_output(output_satoshis, @owner, my_balance, other_balance)
    else
      add_output(output_satoshis, @owner, other_balance, my_balance)
    end
  end
end

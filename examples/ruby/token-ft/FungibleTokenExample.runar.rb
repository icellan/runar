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

  # Companion-parent merge (W8 / SoloMerge): authenticates the companion via
  # other_parent_tx. Input count is not identity. Pin:
  # packages/runar-testing/src/__tests__/w8-token-ft-solo-merge-known-broken.test.ts.
  runar_public sig: Sig, other_balance: Bigint, all_prevouts: ByteString, other_parent_tx: ByteString, output_satoshis: Bigint
  def merge(sig, other_balance, all_prevouts, other_parent_tx, output_satoshis)
    assert check_sig(sig, @owner)
    assert output_satoshis >= 1
    assert other_balance >= 0
    assert len(@token_id) > 0
    pad00 = num2bin(0, 1)
    assert hash256(all_prevouts) == extract_hash_prevouts(@tx_preimage)
    assert len(all_prevouts) >= 72
    my_outpoint = extract_outpoint(@tx_preimage)
    first_outpoint = substr(all_prevouts, 0, 36)
    second_outpoint = substr(all_prevouts, 36, 36)
    companion_outpoint = first_outpoint
    if my_outpoint == first_outpoint
      companion_outpoint = second_outpoint
    else
      assert my_outpoint == second_outpoint
    end
    companion_txid = substr(companion_outpoint, 0, 32)
    companion_vout = bin2num(cat(substr(companion_outpoint, 32, 4), pad00))
    assert companion_vout == 0
    assert hash256(other_parent_tx) == companion_txid
    in_count = bin2num(cat(substr(other_parent_tx, 4, 1), pad00))
    assert in_count >= 1
    assert in_count <= 3
    off = 5
    if 0 < in_count
      sl = bin2num(cat(substr(other_parent_tx, off + 36, 1), pad00))
      assert sl < 253
      off = off + 36 + 1 + sl + 4
    end
    if 1 < in_count
      sl = bin2num(cat(substr(other_parent_tx, off + 36, 1), pad00))
      assert sl < 253
      off = off + 36 + 1 + sl + 4
    end
    if 2 < in_count
      sl = bin2num(cat(substr(other_parent_tx, off + 36, 1), pad00))
      assert sl < 253
      off = off + 36 + 1 + sl + 4
    end
    out_count_marker = bin2num(cat(substr(other_parent_tx, off, 1), pad00))
    out_count = out_count_marker
    out_count_size = 1
    if out_count_marker == 253
      out_count = bin2num(cat(substr(other_parent_tx, off + 1, 2), pad00))
      assert out_count >= 253
      out_count_size = 3
    end
    if out_count_marker == 254
      out_count = bin2num(cat(substr(other_parent_tx, off + 1, 4), pad00))
      assert out_count > 65535
      out_count_size = 5
    end
    if out_count_marker == 255
      out_count = bin2num(cat(substr(other_parent_tx, off + 1, 8), pad00))
      assert out_count > 4294967295
      out_count_size = 9
    end
    assert out_count >= 1
    off = off + out_count_size
    marker = bin2num(cat(substr(other_parent_tx, off + 8, 1), pad00))
    assert marker == 253
    script_len = bin2num(cat(substr(other_parent_tx, off + 9, 2), pad00))
    script_start = off + 11
    assert len(other_parent_tx) >= script_start + script_len
    companion_script = substr(other_parent_tx, script_start, script_len)
    assert script_len > 49
    sc = extract_script_code(@tx_preimage)
    sc_marker = bin2num(cat(substr(sc, 0, 1), pad00))
    assert sc_marker == 253
    my_body = substr(sc, 3, len(sc) - 3)
    companion_body = substr(companion_script, 2, script_len - 2)
    assert len(my_body) == len(companion_body)
    assert len(my_body) > 49
    assert substr(my_body, 0, len(my_body) - 49) == substr(companion_body, 0, len(companion_body) - 49)
    other_primary = bin2num(cat(substr(companion_script, script_len - 16, 8), pad00))
    other_merge = bin2num(cat(substr(companion_script, script_len - 8, 8), pad00))
    assert other_primary + other_merge == other_balance
    my_balance = @balance + @merge_balance
    if my_outpoint == first_outpoint
      add_output(output_satoshis, @owner, my_balance, other_balance)
    else
      add_output(output_satoshis, @owner, other_balance, my_balance)
    end
  end
end

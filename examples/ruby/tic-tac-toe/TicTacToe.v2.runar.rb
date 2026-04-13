require 'runar'

# TicTacToe v2 -- FixedArray rewrite of the hand-rolled v1 contract.
#
# Semantically identical to +TicTacToe.runar.rb+, with the 9 board cells
# expressed as a single +FixedArray[Bigint, 9]+ property.  The Runar
# compiler's +expand_fixed_arrays+ pass desugars this to the same 9 scalar
# siblings that v1 declares manually, so this file must compile to
# byte-identical Bitcoin Script.

class TicTacToe < Runar::StatefulSmartContract
  prop :player_x,      PubKey,     readonly: true
  prop :bet_amount,    Bigint,     readonly: true
  prop :p2pkh_prefix,  ByteString, readonly: true, default: '1976a914'
  prop :p2pkh_suffix,  ByteString, readonly: true, default: '88ac'

  prop :player_o, PubKey,              default: '00' * 33
  prop :board,    FixedArray[Bigint, 9], default: [0, 0, 0, 0, 0, 0, 0, 0, 0]
  prop :turn,     Bigint,              default: 0
  prop :status,   Bigint,              default: 0

  def initialize(player_x, bet_amount)
    super(player_x, bet_amount)
    @player_x   = player_x
    @bet_amount = bet_amount
  end

  runar_public opponent_pk: PubKey, sig: Sig
  def join(opponent_pk, sig)
    assert @status == 0
    assert check_sig(sig, opponent_pk)
    @player_o = opponent_pk
    @status   = 1
    @turn     = 1
  end

  runar_public position: Bigint, player: PubKey, sig: Sig
  def move(position, player, sig)
    assert @status == 1
    assert check_sig(sig, player)
    assert_correct_player(player)
    place_move(position)
    if @turn == 1
      @turn = 2
    else
      @turn = 1
    end
  end

  runar_public position: Bigint, player: PubKey, sig: Sig, change_pkh: ByteString, change_amount: Bigint
  def move_and_win(position, player, sig, change_pkh, change_amount)
    assert @status == 1
    assert check_sig(sig, player)
    assert_correct_player(player)
    assert_cell_empty(position)
    assert check_win_after_move(position, @turn)

    total_payout = @bet_amount * 2
    payout = cat(cat(num2bin(total_payout, 8), @p2pkh_prefix), cat(hash160(player), @p2pkh_suffix))
    if change_amount > 0
      change = cat(cat(num2bin(change_amount, 8), @p2pkh_prefix), cat(change_pkh, @p2pkh_suffix))
      assert hash256(cat(payout, change)) == extract_output_hash(@tx_preimage)
    else
      assert hash256(payout) == extract_output_hash(@tx_preimage)
    end
  end

  runar_public position: Bigint, player: PubKey, sig: Sig, change_pkh: ByteString, change_amount: Bigint
  def move_and_tie(position, player, sig, change_pkh, change_amount)
    assert @status == 1
    assert check_sig(sig, player)
    assert_correct_player(player)
    assert_cell_empty(position)
    assert count_occupied() == 8
    assert !check_win_after_move(position, @turn)

    out1 = cat(cat(num2bin(@bet_amount, 8), @p2pkh_prefix), cat(hash160(@player_x), @p2pkh_suffix))
    out2 = cat(cat(num2bin(@bet_amount, 8), @p2pkh_prefix), cat(hash160(@player_o), @p2pkh_suffix))
    if change_amount > 0
      change = cat(cat(num2bin(change_amount, 8), @p2pkh_prefix), cat(change_pkh, @p2pkh_suffix))
      assert hash256(cat(cat(out1, out2), change)) == extract_output_hash(@tx_preimage)
    else
      assert hash256(cat(out1, out2)) == extract_output_hash(@tx_preimage)
    end
  end

  runar_public sig: Sig, change_pkh: ByteString, change_amount: Bigint
  def cancel_before_join(sig, change_pkh, change_amount)
    assert @status == 0
    assert check_sig(sig, @player_x)
    payout = cat(cat(num2bin(@bet_amount, 8), @p2pkh_prefix), cat(hash160(@player_x), @p2pkh_suffix))
    if change_amount > 0
      change = cat(cat(num2bin(change_amount, 8), @p2pkh_prefix), cat(change_pkh, @p2pkh_suffix))
      assert hash256(cat(payout, change)) == extract_output_hash(@tx_preimage)
    else
      assert hash256(payout) == extract_output_hash(@tx_preimage)
    end
  end

  runar_public sig_x: Sig, sig_o: Sig, change_pkh: ByteString, change_amount: Bigint
  def cancel(sig_x, sig_o, change_pkh, change_amount)
    out1 = cat(cat(num2bin(@bet_amount, 8), @p2pkh_prefix), cat(hash160(@player_x), @p2pkh_suffix))
    out2 = cat(cat(num2bin(@bet_amount, 8), @p2pkh_prefix), cat(hash160(@player_o), @p2pkh_suffix))
    if change_amount > 0
      change = cat(cat(num2bin(change_amount, 8), @p2pkh_prefix), cat(change_pkh, @p2pkh_suffix))
      assert hash256(cat(cat(out1, out2), change)) == extract_output_hash(@tx_preimage)
    else
      assert hash256(cat(out1, out2)) == extract_output_hash(@tx_preimage)
    end
    assert check_sig(sig_x, @player_x)
    assert check_sig(sig_o, @player_o)
  end

  params player: PubKey
  def assert_correct_player(player)
    if @turn == 1
      assert player == @player_x
    else
      assert player == @player_o
    end
  end

  params position: Bigint
  def assert_cell_empty(position)
    if position == 0
      assert @board[0] == 0
    elsif position == 1
      assert @board[1] == 0
    elsif position == 2
      assert @board[2] == 0
    elsif position == 3
      assert @board[3] == 0
    elsif position == 4
      assert @board[4] == 0
    elsif position == 5
      assert @board[5] == 0
    elsif position == 6
      assert @board[6] == 0
    elsif position == 7
      assert @board[7] == 0
    elsif position == 8
      assert @board[8] == 0
    else
      assert false
    end
  end

  params position: Bigint
  def place_move(position)
    assert_cell_empty(position)
    @board[position] = @turn
  end

  params cell_index: Bigint, override_pos: Bigint, override_val: Bigint
  def get_cell_or_override(cell_index, override_pos, override_val)
    if cell_index == override_pos
      return override_val
    end
    if cell_index == 0
      return @board[0]
    elsif cell_index == 1
      return @board[1]
    elsif cell_index == 2
      return @board[2]
    elsif cell_index == 3
      return @board[3]
    elsif cell_index == 4
      return @board[4]
    elsif cell_index == 5
      return @board[5]
    elsif cell_index == 6
      return @board[6]
    elsif cell_index == 7
      return @board[7]
    else
      return @board[8]
    end
  end

  params position: Bigint, player: Bigint
  def check_win_after_move(position, player)
    v0 = get_cell_or_override(0, position, player)
    v1 = get_cell_or_override(1, position, player)
    v2 = get_cell_or_override(2, position, player)
    v3 = get_cell_or_override(3, position, player)
    v4 = get_cell_or_override(4, position, player)
    v5 = get_cell_or_override(5, position, player)
    v6 = get_cell_or_override(6, position, player)
    v7 = get_cell_or_override(7, position, player)
    v8 = get_cell_or_override(8, position, player)

    if v0 == player && v1 == player && v2 == player
      return true
    end
    if v3 == player && v4 == player && v5 == player
      return true
    end
    if v6 == player && v7 == player && v8 == player
      return true
    end
    if v0 == player && v3 == player && v6 == player
      return true
    end
    if v1 == player && v4 == player && v7 == player
      return true
    end
    if v2 == player && v5 == player && v8 == player
      return true
    end
    if v0 == player && v4 == player && v8 == player
      return true
    end
    if v2 == player && v4 == player && v6 == player
      return true
    end
    return false
  end

  def count_occupied
    count = 0
    if @board[0] != 0
      count = count + 1
    end
    if @board[1] != 0
      count = count + 1
    end
    if @board[2] != 0
      count = count + 1
    end
    if @board[3] != 0
      count = count + 1
    end
    if @board[4] != 0
      count = count + 1
    end
    if @board[5] != 0
      count = count + 1
    end
    if @board[6] != 0
      count = count + 1
    end
    if @board[7] != 0
      count = count + 1
    end
    if @board[8] != 0
      count = count + 1
    end
    return count
  end
end

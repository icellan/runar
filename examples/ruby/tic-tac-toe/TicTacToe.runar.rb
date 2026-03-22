require 'runar'

# TicTacToe -- On-chain Tic-Tac-Toe contract.
#
# Two players compete on a 3x3 board. Each move is an on-chain transaction.
# The contract holds both players' bets and enforces correct game rules
# entirely in Bitcoin Script.
#
# Board encoding:
#   Since Runar has no arrays, the 3x3 board uses 9 individual bigint
#   fields (c0-c8). Values: 0=empty, 1=X, 2=O.
#
# Lifecycle:
#   1. Player X deploys the contract with their bet amount.
#   2. Player O calls join() to enter the game, adding their bet.
#   3. Players alternate calling move() (non-terminal) or
#      move_and_win() / move_and_tie() (terminal).
#   4. Either player can propose cancel() (requires both signatures).

class TicTacToe < Runar::StatefulSmartContract
  prop :player_x,      PubKey,     readonly: true
  prop :bet_amount,    Bigint,     readonly: true
  prop :p2pkh_prefix,  ByteString, readonly: true, default: '1976a914'
  prop :p2pkh_suffix,  ByteString, readonly: true, default: '88ac'

  prop :player_o, PubKey,  default: '00' * 33
  prop :c0,       Bigint,  default: 0
  prop :c1,       Bigint,  default: 0
  prop :c2,       Bigint,  default: 0
  prop :c3,       Bigint,  default: 0
  prop :c4,       Bigint,  default: 0
  prop :c5,       Bigint,  default: 0
  prop :c6,       Bigint,  default: 0
  prop :c7,       Bigint,  default: 0
  prop :c8,       Bigint,  default: 0
  prop :turn,     Bigint,  default: 0
  prop :status,   Bigint,  default: 0

  def initialize(player_x, bet_amount)
    super(player_x, bet_amount)
    @player_x   = player_x
    @bet_amount = bet_amount
  end

  # Player O joins the game.
  # State-mutating: produces continuation UTXO with doubled bet.
  runar_public opponent_pk: PubKey, sig: Sig
  def join(opponent_pk, sig)
    assert @status == 0
    assert check_sig(sig, opponent_pk)
    @player_o = opponent_pk
    @status   = 1
    @turn     = 1
  end

  # Make a non-terminal move. Updates board and flips turn.
  # State-mutating: produces continuation UTXO.
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

  # Make a winning move. Non-mutating terminal method.
  # Enforces winner-gets-all payout via extract_output_hash.
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

  # Make a move that fills the board (tie). Non-mutating terminal method.
  # Enforces equal split payout via extract_output_hash.
  runar_public position: Bigint, player: PubKey, sig: Sig, change_pkh: ByteString, change_amount: Bigint
  def move_and_tie(position, player, sig, change_pkh, change_amount)
    assert @status == 1
    assert check_sig(sig, player)
    assert_correct_player(player)
    assert_cell_empty(position)
    assert count_occupied == 8
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

  # Player X cancels before anyone joins. Non-mutating terminal method.
  # Refunds the full bet to player X.
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

  # Both players agree to cancel. Non-mutating terminal method.
  # Enforces equal refund via extract_output_hash.
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

  # --- Private helpers ---

  # Assert the provided player pubkey matches whoever's turn it is.
  def assert_correct_player(player)
    if @turn == 1
      assert player == @player_x
    else
      assert player == @player_o
    end
  end

  # Assert the cell at the given position is empty.
  def assert_cell_empty(position)
    if position == 0
      assert @c0 == 0
    elsif position == 1
      assert @c1 == 0
    elsif position == 2
      assert @c2 == 0
    elsif position == 3
      assert @c3 == 0
    elsif position == 4
      assert @c4 == 0
    elsif position == 5
      assert @c5 == 0
    elsif position == 6
      assert @c6 == 0
    elsif position == 7
      assert @c7 == 0
    elsif position == 8
      assert @c8 == 0
    else
      assert false
    end
  end

  # Place the current turn's mark at the given position.
  def place_move(position)
    assert_cell_empty(position)
    if position == 0
      @c0 = @turn
    elsif position == 1
      @c1 = @turn
    elsif position == 2
      @c2 = @turn
    elsif position == 3
      @c3 = @turn
    elsif position == 4
      @c4 = @turn
    elsif position == 5
      @c5 = @turn
    elsif position == 6
      @c6 = @turn
    elsif position == 7
      @c7 = @turn
    elsif position == 8
      @c8 = @turn
    else
      assert false
    end
  end

  # Get cell value, overriding the specified position with override_val.
  def get_cell_or_override(cell_index, override_pos, override_val)
    return override_val if cell_index == override_pos

    if cell_index == 0
      @c0
    elsif cell_index == 1
      @c1
    elsif cell_index == 2
      @c2
    elsif cell_index == 3
      @c3
    elsif cell_index == 4
      @c4
    elsif cell_index == 5
      @c5
    elsif cell_index == 6
      @c6
    elsif cell_index == 7
      @c7
    else
      @c8
    end
  end

  # Check if placing player's mark at position would create a winning line.
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

    return true if v0 == player && v1 == player && v2 == player
    return true if v3 == player && v4 == player && v5 == player
    return true if v6 == player && v7 == player && v8 == player
    return true if v0 == player && v3 == player && v6 == player
    return true if v1 == player && v4 == player && v7 == player
    return true if v2 == player && v5 == player && v8 == player
    return true if v0 == player && v4 == player && v8 == player
    return true if v2 == player && v4 == player && v6 == player

    false
  end

  # Count the number of occupied cells on the board.
  def count_occupied
    count = 0
    count += 1 if @c0 != 0
    count += 1 if @c1 != 0
    count += 1 if @c2 != 0
    count += 1 if @c3 != 0
    count += 1 if @c4 != 0
    count += 1 if @c5 != 0
    count += 1 if @c6 != 0
    count += 1 if @c7 != 0
    count += 1 if @c8 != 0
    count
  end
end

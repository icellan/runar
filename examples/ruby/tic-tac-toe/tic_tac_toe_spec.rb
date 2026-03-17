# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'TicTacToe.runar'

PLAYER_X  = Runar::TestKeys::ALICE.pub_key
PLAYER_O  = Runar::TestKeys::BOB.pub_key
ZERO_PK   = '00' * 33
BET_AMOUNT = 1000

# Create a TicTacToe contract in the initial (waiting) state.
def make_game(**overrides)
  player_x   = overrides.delete(:player_x)   || PLAYER_X
  bet_amount = overrides.delete(:bet_amount)  || BET_AMOUNT
  game = TicTacToe.new(player_x, bet_amount)

  # Apply initialized-property defaults, then overrides
  defaults = {
    player_o: ZERO_PK, c0: 0, c1: 0, c2: 0,
    c3: 0, c4: 0, c5: 0, c6: 0, c7: 0, c8: 0,
    turn: 0, status: 0,
    p2pkh_prefix: '1976a914', p2pkh_suffix: '88ac'
  }
  defaults.merge(overrides).each { |attr, val| game.instance_variable_set(:"@#{attr}", val) }
  game
end

# Create a TicTacToe contract in the playing state (after join).
def make_playing_game(**overrides)
  defaults = { player_o: PLAYER_O, status: 1, turn: 1 }
  make_game(**defaults.merge(overrides))
end

RSpec.describe TicTacToe do
  describe 'join' do
    it 'player O can join a waiting game' do
      game = make_game
      game.join(PLAYER_O, Runar::TestKeys::BOB.test_sig)
      expect(game.player_o).to eq(PLAYER_O)
      expect(game.status).to eq(1)
      expect(game.turn).to eq(1)
    end

    it 'cannot join a game that is already in progress' do
      game = make_playing_game
      expect { game.join(PLAYER_O, Runar::TestKeys::BOB.test_sig) }.to raise_error(RuntimeError)
    end
  end

  describe 'move' do
    it 'player X can place a mark on an empty cell' do
      game = make_playing_game
      game.move(0, PLAYER_X, Runar::TestKeys::ALICE.test_sig)
      expect(game.c0).to eq(1)
      expect(game.turn).to eq(2)
    end

    it 'player O can place a mark on their turn' do
      game = make_playing_game(turn: 2)
      game.move(4, PLAYER_O, Runar::TestKeys::BOB.test_sig)
      expect(game.c4).to eq(2)
      expect(game.turn).to eq(1)
    end

    it 'cannot place a mark on an occupied cell' do
      game = make_playing_game(c0: 1)
      expect { game.move(0, PLAYER_X, Runar::TestKeys::ALICE.test_sig) }.to raise_error(RuntimeError)
    end

    it 'cannot move when game status is not playing' do
      game = make_game
      expect { game.move(0, PLAYER_X, Runar::TestKeys::ALICE.test_sig) }.to raise_error(RuntimeError)
    end

    it 'each board position (0-8) can be played' do
      9.times do |pos|
        game = make_playing_game
        game.move(pos, PLAYER_X, Runar::TestKeys::ALICE.test_sig)
        expect(game.instance_variable_get(:"@c#{pos}")).to eq(1)
      end
    end

    it 'position 9 (out of range) is rejected' do
      game = make_playing_game
      expect { game.move(9, PLAYER_X, Runar::TestKeys::ALICE.test_sig) }.to raise_error(RuntimeError)
    end
  end

  describe 'full game flow' do
    it 'join + moves + X wins top row' do
      game = make_game

      # Player O joins
      game.join(PLAYER_O, Runar::TestKeys::BOB.test_sig)
      expect(game.status).to eq(1)
      expect(game.turn).to eq(1)

      # X@0, O@3, X@1, O@4 -- set up X to win with position 2 (top row)
      game.move(0, PLAYER_X, Runar::TestKeys::ALICE.test_sig)
      expect(game.c0).to eq(1)

      game.move(3, PLAYER_O, Runar::TestKeys::BOB.test_sig)
      expect(game.c3).to eq(2)

      game.move(1, PLAYER_X, Runar::TestKeys::ALICE.test_sig)
      expect(game.c1).to eq(1)

      game.move(4, PLAYER_O, Runar::TestKeys::BOB.test_sig)
      expect(game.c4).to eq(2)
      expect(game.turn).to eq(1) # X's turn

      # X plays position 2 to win top row (0,1,2).
      # Pre-compute the payout hash so extract_output_hash returns the right value.
      total_payout = game.bet_amount * 2
      payout = cat(
        cat(num2bin(total_payout, 8), game.p2pkh_prefix),
        cat(hash160(PLAYER_X), game.p2pkh_suffix)
      )
      game.tx_preimage = hash256(payout)
      expect { game.move_and_win(2, PLAYER_X, Runar::TestKeys::ALICE.test_sig, '00', 0) }.not_to raise_error
    end
  end

  describe 'win detection' do
    it 'X wins with top row (positions 0, 1, 2)' do
      game = make_playing_game(c0: 1, c1: 1)
      expect(game.check_win_after_move(2, 1)).to be(true)
    end

    it 'X wins with left column (positions 0, 3, 6)' do
      game = make_playing_game(c0: 1, c3: 1)
      expect(game.check_win_after_move(6, 1)).to be(true)
    end

    it 'X wins with main diagonal (positions 0, 4, 8)' do
      game = make_playing_game(c0: 1, c4: 1)
      expect(game.check_win_after_move(8, 1)).to be(true)
    end

    it 'O wins with anti-diagonal (positions 2, 4, 6)' do
      game = make_playing_game(c2: 2, c4: 2)
      expect(game.check_win_after_move(6, 2)).to be(true)
    end

    it 'no winning condition when positions do not form a line' do
      game = make_playing_game(c0: 1, c1: 2)
      expect(game.check_win_after_move(2, 1)).to be(false)
    end
  end

  describe 'count_occupied' do
    it 'empty board has 0 occupied cells' do
      game = make_playing_game
      expect(game.count_occupied).to eq(0)
    end

    it 'returns correct number of occupied cells' do
      game = make_playing_game(c0: 1, c4: 2, c8: 1)
      expect(game.count_occupied).to eq(3)
    end
  end
end

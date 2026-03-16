import pytest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract

contract_mod = load_contract(str(Path(__file__).parent / "TicTacToe.runar.py"))
TicTacToe = contract_mod.TicTacToe

from runar import ALICE, BOB

# Use real test keys as hex strings (TicTacToe uses hex-encoded pubkeys)
PLAYER_X = ALICE.pub_key.hex()
PLAYER_O = BOB.pub_key.hex()
ZERO_PK = "00" * 33
BET_AMOUNT = 1000


def make_game(**overrides):
    """Create a TicTacToe contract in the initial (waiting) state."""
    player_x = overrides.pop("player_x", PLAYER_X)
    bet_amount = overrides.pop("bet_amount", BET_AMOUNT)
    game = TicTacToe(player_x=player_x, bet_amount=bet_amount)
    # Set initialized-property defaults, then apply overrides
    defaults = dict(
        player_o=ZERO_PK, c0=0, c1=0, c2=0,
        c3=0, c4=0, c5=0, c6=0, c7=0, c8=0,
        turn=0, status=0,
        p2pkh_prefix="1976a914", p2pkh_suffix="88ac",
    )
    defaults.update(overrides)
    for attr, val in defaults.items():
        setattr(game, attr, val)
    return game


def make_playing_game(**overrides):
    """Create a TicTacToe contract in the playing state (after join)."""
    defaults = dict(
        player_o=PLAYER_O,
        status=1,
        turn=1,
    )
    defaults.update(overrides)
    return make_game(**defaults)


class TestJoin:

    def test_join(self):
        """Player O can join a waiting game."""
        game = make_game()
        game.join(PLAYER_O, BOB.test_sig)
        assert game.player_o == PLAYER_O
        assert game.status == 1
        assert game.turn == 1

    def test_join_rejects_when_already_playing(self):
        """Cannot join a game that is already in progress."""
        game = make_playing_game()
        with pytest.raises(AssertionError):
            game.join(PLAYER_O, BOB.test_sig)


class TestMove:

    def test_move_player_x(self):
        """Player X can place a mark on an empty cell."""
        game = make_playing_game()
        game.move(0, PLAYER_X, ALICE.test_sig)
        assert game.c0 == 1
        assert game.turn == 2

    def test_move_player_o(self):
        """Player O can place a mark on their turn."""
        game = make_playing_game(turn=2)
        game.move(4, PLAYER_O, BOB.test_sig)
        assert game.c4 == 2
        assert game.turn == 1

    def test_move_rejects_occupied(self):
        """Cannot place a mark on an occupied cell."""
        game = make_playing_game(c0=1)
        with pytest.raises(AssertionError):
            game.move(0, PLAYER_X, ALICE.test_sig)

    def test_move_rejects_when_not_playing(self):
        """Cannot move when game status is not 'playing'."""
        game = make_game()
        with pytest.raises(AssertionError):
            game.move(0, PLAYER_X, ALICE.test_sig)

    def test_full_game_flow(self):
        """Play through join + moves + X wins top row."""
        game = make_game()

        # Player O joins
        game.join(PLAYER_O, BOB.test_sig)
        assert game.status == 1
        assert game.turn == 1

        # X@0, O@3, X@1, O@4 — set up X to win with position 2 (top row)
        game.move(0, PLAYER_X, ALICE.test_sig)
        assert game.c0 == 1

        game.move(3, PLAYER_O, BOB.test_sig)
        assert game.c3 == 2

        game.move(1, PLAYER_X, ALICE.test_sig)
        assert game.c1 == 1

        game.move(4, PLAYER_O, BOB.test_sig)
        assert game.c4 == 2
        assert game.turn == 1  # X's turn

        # X plays position 2 to win top row (0,1,2).
        # Pre-compute the payout hash so extract_output_hash returns the right value.
        from runar import hash160, hash256, num2bin, cat
        total_payout = game.bet_amount * 2
        payout = cat(cat(num2bin(total_payout, 8), game.p2pkh_prefix),
                     cat(hash160(PLAYER_X), game.p2pkh_suffix))
        game.tx_preimage = hash256(payout)
        game.move_and_win(2, PLAYER_X, ALICE.test_sig, "00", 0)

    def test_all_positions(self):
        """Each board position (0-8) can be played."""
        for pos in range(9):
            game = make_playing_game()
            game.move(pos, PLAYER_X, ALICE.test_sig)
            assert getattr(game, f"c{pos}") == 1

    def test_move_rejects_invalid_position(self):
        """Position 9 (out of range) is rejected."""
        game = make_playing_game()
        with pytest.raises(AssertionError):
            game.move(9, PLAYER_X, ALICE.test_sig)


class TestWinDetection:

    def test_check_win_row(self):
        """X wins with top row (positions 0, 1, 2)."""
        game = make_playing_game(c0=1, c1=1)
        assert game.check_win_after_move(2, 1)

    def test_check_win_column(self):
        """X wins with left column (positions 0, 3, 6)."""
        game = make_playing_game(c0=1, c3=1)
        assert game.check_win_after_move(6, 1)

    def test_check_win_diagonal(self):
        """X wins with main diagonal (positions 0, 4, 8)."""
        game = make_playing_game(c0=1, c4=1)
        assert game.check_win_after_move(8, 1)

    def test_check_win_anti_diagonal(self):
        """O wins with anti-diagonal (positions 2, 4, 6)."""
        game = make_playing_game(c2=2, c4=2)
        assert game.check_win_after_move(6, 2)

    def test_no_win(self):
        """No winning condition when positions don't form a line."""
        game = make_playing_game(c0=1, c1=2)
        assert not game.check_win_after_move(2, 1)


class TestCountOccupied:

    def test_count_occupied_empty(self):
        """Empty board has 0 occupied cells."""
        game = make_playing_game()
        assert game.count_occupied() == 0

    def test_count_occupied_some(self):
        """Count returns correct number of occupied cells."""
        game = make_playing_game(c0=1, c4=2, c8=1)
        assert game.count_occupied() == 3


def test_compile():
    from pathlib import Path
    from runar import compile_check
    source_path = str(Path(__file__).parent / "TicTacToe.runar.py")
    with open(source_path) as f:
        source = f.read()
    compile_check(source, "TicTacToe.runar.py")

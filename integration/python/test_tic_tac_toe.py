"""
TicTacToe integration test -- stateful contract with multi-method game flow.

TicTacToe is a StatefulSmartContract with properties:
    - playerX: PubKey (readonly)
    - betAmount: bigint (readonly)
    - p2pkhPrefix: ByteString (readonly, initialized)
    - p2pkhSuffix: ByteString (readonly, initialized)
    - playerO: PubKey (mutable, initialized to zero)
    - c0..c8: bigint (mutable, initialized to 0)
    - turn: bigint (mutable, initialized to 0)
    - status: bigint (mutable, initialized to 0)

Methods:
    - join(opponentPK, sig) -- state-mutating, Player O joins
    - move(position, player, sig) -- state-mutating, place a mark
    - moveAndWin(position, player, sig, changePKH, changeAmount) -- terminal
    - moveAndTie(position, player, sig, changePKH, changeAmount) -- terminal
    - cancelBeforeJoin(sig, changePKH, changeAmount) -- terminal
    - cancel(sigX, sigO, changePKH, changeAmount) -- terminal

The SDK auto-computes Sig params when None is passed.
"""

import pytest

from conftest import (
    compile_contract_ts, create_provider, create_funded_wallet, create_wallet,
)
from runar.sdk import RunarContract, DeployOptions, CallOptions, TerminalOutput


ZERO_PK = "00" * 33


class TestTicTacToe:

    def test_compile(self):
        """Compile the TicTacToe contract."""
        artifact = compile_contract_ts("examples/ts/tic-tac-toe/TicTacToe.runar.ts")
        assert artifact
        assert artifact.contract_name == "TicTacToe"

    def test_deploy(self):
        """Deploy TicTacToe with player X's pubkey and bet amount."""
        artifact = compile_contract_ts("examples/ts/tic-tac-toe/TicTacToe.runar.ts")

        provider = create_provider()
        player_x_wallet = create_funded_wallet(provider)

        contract = RunarContract(artifact, [
            player_x_wallet["pubKeyHex"],
            5000,
        ])

        txid, _ = contract.deploy(
            provider, player_x_wallet["signer"],
            DeployOptions(satoshis=5000),
        )
        assert txid
        assert isinstance(txid, str)
        assert len(txid) == 64

    def test_join(self):
        """Deploy and call join -- Player O enters the game."""
        artifact = compile_contract_ts("examples/ts/tic-tac-toe/TicTacToe.runar.ts")

        provider = create_provider()
        player_x_wallet = create_funded_wallet(provider)
        player_o_wallet = create_funded_wallet(provider)

        contract = RunarContract(artifact, [
            player_x_wallet["pubKeyHex"],
            5000,
        ])

        contract.deploy(
            provider, player_x_wallet["signer"],
            DeployOptions(satoshis=5000),
        )

        # join(opponentPK, sig) -- sig is auto-computed (None)
        # Signer must be playerO because checkSig verifies against opponentPK
        call_txid, _ = contract.call(
            "join",
            [player_o_wallet["pubKeyHex"], None],
            provider, player_o_wallet["signer"],
        )
        assert call_txid
        assert len(call_txid) == 64

    def test_move(self):
        """Deploy, join, then make a move -- Player X places at position 4."""
        artifact = compile_contract_ts("examples/ts/tic-tac-toe/TicTacToe.runar.ts")

        provider = create_provider()
        player_x_wallet = create_funded_wallet(provider)
        player_o_wallet = create_funded_wallet(provider)

        contract = RunarContract(artifact, [
            player_x_wallet["pubKeyHex"],
            5000,
        ])

        contract.deploy(
            provider, player_x_wallet["signer"],
            DeployOptions(satoshis=5000),
        )

        # Player O joins
        contract.call(
            "join",
            [player_o_wallet["pubKeyHex"], None],
            provider, player_o_wallet["signer"],
        )

        # Player X moves to center (position 4)
        # move(position, player, sig) -- sig is auto-computed
        call_txid, _ = contract.call(
            "move",
            [4, player_x_wallet["pubKeyHex"], None],
            provider, player_x_wallet["signer"],
        )
        assert call_txid
        assert len(call_txid) == 64

    def test_full_game(self):
        """Deploy, join, play moves, X wins top row with moveAndWin."""
        artifact = compile_contract_ts("examples/ts/tic-tac-toe/TicTacToe.runar.ts")

        provider = create_provider()
        player_x_wallet = create_funded_wallet(provider)
        player_o_wallet = create_funded_wallet(provider)

        bet_amount = 1000
        contract = RunarContract(artifact, [
            player_x_wallet["pubKeyHex"],
            bet_amount,
        ])

        contract.deploy(
            provider, player_x_wallet["signer"],
            DeployOptions(satoshis=bet_amount),
        )

        # Player O joins — doubling the pot (betAmount * 2)
        contract.call(
            "join",
            [player_o_wallet["pubKeyHex"], None],
            provider, player_o_wallet["signer"],
            CallOptions(satoshis=bet_amount * 2),
        )

        # X@0, O@3, X@1, O@4 — set up X to win with position 2 (top row)
        contract.call(
            "move",
            [0, player_x_wallet["pubKeyHex"], None],
            provider, player_x_wallet["signer"],
        )

        contract.call(
            "move",
            [3, player_o_wallet["pubKeyHex"], None],
            provider, player_o_wallet["signer"],
        )

        contract.call(
            "move",
            [1, player_x_wallet["pubKeyHex"], None],
            provider, player_x_wallet["signer"],
        )

        contract.call(
            "move",
            [4, player_o_wallet["pubKeyHex"], None],
            provider, player_o_wallet["signer"],
        )

        # Board: X X _ | O O _ | _ _ _ — X plays position 2 to win top row
        # moveAndWin(position, player, sig, changePKH, changeAmount)
        total_payout = bet_amount * 2
        winner_p2pkh = "76a914" + player_x_wallet["pubKeyHash"] + "88ac"

        call_txid, _ = contract.call(
            "moveAndWin",
            [2, player_x_wallet["pubKeyHex"], None, "00" * 20, 0],
            provider, player_x_wallet["signer"],
            CallOptions(terminal_outputs=[
                TerminalOutput(script_hex=winner_p2pkh, satoshis=total_payout),
            ]),
        )
        assert call_txid
        assert len(call_txid) == 64

    def test_wrong_player_rejected(self):
        """Move with wrong player's signer should be rejected (checkSig fails)."""
        artifact = compile_contract_ts("examples/ts/tic-tac-toe/TicTacToe.runar.ts")

        provider = create_provider()
        player_x_wallet = create_funded_wallet(provider)
        player_o_wallet = create_funded_wallet(provider)

        contract = RunarContract(artifact, [
            player_x_wallet["pubKeyHex"],
            5000,
        ])

        contract.deploy(
            provider, player_x_wallet["signer"],
            DeployOptions(satoshis=5000),
        )

        # Player O joins
        contract.call(
            "join",
            [player_o_wallet["pubKeyHex"], None],
            provider, player_o_wallet["signer"],
        )

        # It's Player X's turn (turn=1), but Player O tries to move
        # Passing playerO's pubkey with playerO's signer -- assertCorrectPlayer
        # will fail because turn==1 expects playerX's pubkey
        with pytest.raises(Exception):
            contract.call(
                "move",
                [4, player_o_wallet["pubKeyHex"], None],
                provider, player_o_wallet["signer"],
            )

    def test_join_after_playing_rejected(self):
        """Calling join after the game has already started should be rejected."""
        artifact = compile_contract_ts("examples/ts/tic-tac-toe/TicTacToe.runar.ts")

        provider = create_provider()
        player_x_wallet = create_funded_wallet(provider)
        player_o_wallet = create_funded_wallet(provider)
        intruder_wallet = create_funded_wallet(provider)

        contract = RunarContract(artifact, [
            player_x_wallet["pubKeyHex"],
            5000,
        ])

        contract.deploy(
            provider, player_x_wallet["signer"],
            DeployOptions(satoshis=5000),
        )

        # Player O joins
        contract.call(
            "join",
            [player_o_wallet["pubKeyHex"], None],
            provider, player_o_wallet["signer"],
        )

        # Another player tries to join again -- status is now 1, assert(status==0) fails
        with pytest.raises(Exception):
            contract.call(
                "join",
                [intruder_wallet["pubKeyHex"], None],
                provider, intruder_wallet["signer"],
            )

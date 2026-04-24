package runar.examples.tictactoe;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Bigint;
import runar.lang.types.ByteString;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.checkSig;

/**
 * TicTacToe -- simplified on-chain Tic-Tac-Toe contract.
 *
 * <p>Ports {@code examples/go/tic-tac-toe/TicTacToe.runar.go} to Java,
 * focussing on the state-mutating happy paths (Join + Move). The payout
 * / cancellation paths use {@code extractOutputHash}-based output
 * commitments which are already exercised by the CovenantVault port,
 * so they are omitted here to keep this example compact.
 *
 * <p>Since Rúnar has no runtime-sized arrays, the 3x3 board is spelled
 * out as nine individual {@code Bigint} cells. Values: 0 = empty,
 * 1 = X, 2 = O.
 */
class TicTacToe extends StatefulSmartContract {

    @Readonly PubKey playerX;
    @Readonly Bigint betAmount;
    PubKey playerO;
    Bigint c0;
    Bigint c1;
    Bigint c2;
    Bigint c3;
    Bigint c4;
    Bigint c5;
    Bigint c6;
    Bigint c7;
    Bigint c8;
    Bigint turn;
    Bigint status;                     // 0 = waiting for join, 1 = in progress

    TicTacToe(
        PubKey playerX,
        Bigint betAmount,
        PubKey playerO,
        Bigint c0, Bigint c1, Bigint c2,
        Bigint c3, Bigint c4, Bigint c5,
        Bigint c6, Bigint c7, Bigint c8,
        Bigint turn,
        Bigint status
    ) {
        super(playerX, betAmount, playerO, c0, c1, c2, c3, c4, c5, c6, c7, c8, turn, status);
        this.playerX = playerX;
        this.betAmount = betAmount;
        this.playerO = playerO;
        this.c0 = c0; this.c1 = c1; this.c2 = c2;
        this.c3 = c3; this.c4 = c4; this.c5 = c5;
        this.c6 = c6; this.c7 = c7; this.c8 = c8;
        this.turn = turn;
        this.status = status;
    }

    /** Player O joins an open game. */
    @Public
    void join(PubKey opponentPK, Sig sig) {
        assertThat(this.status.eq(Bigint.ZERO));
        assertThat(checkSig(sig, opponentPK));
        this.playerO = opponentPK;
        this.status = Bigint.ONE;
        this.turn = Bigint.ONE;
    }

    /** A non-terminal move updates the board and flips the turn. */
    @Public
    void move(Bigint position, PubKey player, Sig sig) {
        assertThat(this.status.eq(Bigint.ONE));
        assertThat(checkSig(sig, player));
        assertCorrectPlayer(player);
        placeMove(position);
        if (this.turn.eq(Bigint.ONE)) {
            this.turn = Bigint.TWO;
        } else {
            this.turn = Bigint.ONE;
        }
    }

    // --- private helpers ---

    private void assertCorrectPlayer(PubKey player) {
        if (this.turn.eq(Bigint.ONE)) {
            assertThat(player.equals(this.playerX));
        } else {
            assertThat(player.equals(this.playerO));
        }
    }

    private void placeMove(Bigint position) {
        // Assert the cell is empty before writing it.
        if (position.eq(Bigint.ZERO))      { assertThat(this.c0.eq(Bigint.ZERO)); this.c0 = this.turn; }
        else if (position.eq(Bigint.ONE))  { assertThat(this.c1.eq(Bigint.ZERO)); this.c1 = this.turn; }
        else if (position.eq(Bigint.TWO))  { assertThat(this.c2.eq(Bigint.ZERO)); this.c2 = this.turn; }
        else if (position.eq(Bigint.of(3))) { assertThat(this.c3.eq(Bigint.ZERO)); this.c3 = this.turn; }
        else if (position.eq(Bigint.of(4))) { assertThat(this.c4.eq(Bigint.ZERO)); this.c4 = this.turn; }
        else if (position.eq(Bigint.of(5))) { assertThat(this.c5.eq(Bigint.ZERO)); this.c5 = this.turn; }
        else if (position.eq(Bigint.of(6))) { assertThat(this.c6.eq(Bigint.ZERO)); this.c6 = this.turn; }
        else if (position.eq(Bigint.of(7))) { assertThat(this.c7.eq(Bigint.ZERO)); this.c7 = this.turn; }
        else if (position.eq(Bigint.of(8))) { assertThat(this.c8.eq(Bigint.ZERO)); this.c8 = this.turn; }
        else                                { assertThat(false); }
    }
}

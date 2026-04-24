package runar.examples.tictactoe;

import org.junit.jupiter.api.Test;
import runar.lang.runtime.ContractSimulator;
import runar.lang.types.Bigint;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class TicTacToeTest {

    private static final PubKey ALICE = PubKey.fromHex("020000000000000000000000000000000000000000000000000000000000000001");
    private static final PubKey BOB   = PubKey.fromHex("020000000000000000000000000000000000000000000000000000000000000002");
    private static final PubKey ZERO_PK = PubKey.fromHex("02" + "00".repeat(32));
    private static final Sig SIG = Sig.fromHex("30440220" + "00".repeat(32) + "0220" + "00".repeat(32));

    private TicTacToe freshGame() {
        return new TicTacToe(
            ALICE, Bigint.of(1000),
            ZERO_PK,
            Bigint.ZERO, Bigint.ZERO, Bigint.ZERO,
            Bigint.ZERO, Bigint.ZERO, Bigint.ZERO,
            Bigint.ZERO, Bigint.ZERO, Bigint.ZERO,
            Bigint.ZERO,
            Bigint.ZERO
        );
    }

    @Test
    void joinActivatesGame() {
        TicTacToe g = freshGame();
        ContractSimulator sim = ContractSimulator.stateful(g);
        sim.call("join", BOB, SIG);
        assertEquals(BOB, g.playerO);
        assertEquals(Bigint.ONE, g.status);
        assertEquals(Bigint.ONE, g.turn);
    }

    @Test
    void moveFlipsTurn() {
        TicTacToe g = freshGame();
        ContractSimulator sim = ContractSimulator.stateful(g);
        sim.call("join", BOB, SIG);
        sim.call("move", Bigint.ZERO, ALICE, SIG); // turn was X (1), Alice plays cell 0
        assertEquals(Bigint.ONE, g.c0);
        assertEquals(Bigint.TWO, g.turn);
    }

    @Test
    void moveRejectsOccupiedCell() {
        TicTacToe g = freshGame();
        ContractSimulator sim = ContractSimulator.stateful(g);
        sim.call("join", BOB, SIG);
        sim.call("move", Bigint.ZERO, ALICE, SIG);
        // Bob tries to play on the occupied cell 0.
        assertThrows(AssertionError.class, () -> sim.call("move", Bigint.ZERO, BOB, SIG));
    }

    @Test
    void moveRejectsWrongPlayer() {
        TicTacToe g = freshGame();
        ContractSimulator sim = ContractSimulator.stateful(g);
        sim.call("join", BOB, SIG);
        // Turn is 1 (X = Alice), but Bob tries to move.
        assertThrows(AssertionError.class, () -> sim.call("move", Bigint.ZERO, BOB, SIG));
    }
}

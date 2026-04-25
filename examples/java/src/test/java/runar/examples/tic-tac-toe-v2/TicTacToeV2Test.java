package runar.examples.tictactoev2;

import org.junit.jupiter.api.Test;
import runar.lang.runtime.ContractSimulator;
import runar.lang.types.Bigint;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Surface + simulator tests for the FixedArray-backed {@link TicTacToe}
 * v2 contract. Mirrors the Python pytest suite; covers join + move
 * happy paths and a basic rejection.
 */
class TicTacToeV2Test {

    private static final PubKey PLAYER_X = PubKey.fromHex("020000000000000000000000000000000000000000000000000000000000000001");
    private static final PubKey PLAYER_O = PubKey.fromHex("020000000000000000000000000000000000000000000000000000000000000002");
    private static final Sig SIG = Sig.fromHex("30440220" + "00".repeat(32) + "0220" + "00".repeat(32));

    @Test
    void contractInstantiates() {
        TicTacToe c = new TicTacToe(PLAYER_X, Bigint.of(1000));
        assertNotNull(c);
        assertEquals(Bigint.ZERO, c.status);
        assertEquals(Bigint.ZERO, c.turn);
    }

    @Test
    void joinTransitionsToInProgress() {
        TicTacToe c = new TicTacToe(PLAYER_X, Bigint.of(1000));
        ContractSimulator sim = ContractSimulator.stateful(c);
        sim.call("join", PLAYER_O, SIG);
        assertEquals(Bigint.ONE, c.status);
        assertEquals(Bigint.ONE, c.turn);
        assertEquals(PLAYER_O, c.playerO);
    }

    @Test
    void moveFlipsTurn() {
        TicTacToe c = new TicTacToe(PLAYER_X, Bigint.of(1000));
        ContractSimulator sim = ContractSimulator.stateful(c);
        sim.call("join", PLAYER_O, SIG);
        sim.call("move", Bigint.ZERO, PLAYER_X, SIG);
        assertEquals(Bigint.TWO, c.turn);
        assertEquals(Bigint.ONE, c.board.get(0));
    }

    @Test
    void moveRejectsOccupiedCell() {
        TicTacToe c = new TicTacToe(PLAYER_X, Bigint.of(1000));
        ContractSimulator sim = ContractSimulator.stateful(c);
        sim.call("join", PLAYER_O, SIG);
        sim.call("move", Bigint.ZERO, PLAYER_X, SIG);
        // Now player O tries to move onto the same cell; expect AssertionError.
        assertThrows(
            AssertionError.class,
            () -> sim.call("move", Bigint.ZERO, PLAYER_O, SIG)
        );
    }
}

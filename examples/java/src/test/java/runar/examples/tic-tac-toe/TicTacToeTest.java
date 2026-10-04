package runar.examples.tictactoe;

import java.math.BigInteger;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import runar.lang.runtime.ContractSimulator;
import runar.lang.runtime.Preimage;
import runar.lang.sdk.CompileCheck;
import runar.lang.types.Bigint;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

class TicTacToeTest {

    private static final PubKey ALICE = PubKey.fromHex("020000000000000000000000000000000000000000000000000000000000000001");
    private static final PubKey BOB   = PubKey.fromHex("020000000000000000000000000000000000000000000000000000000000000002");
    private static final PubKey ZERO_PK = PubKey.fromHex("02" + "00".repeat(32));
    private static final Sig SIG = Sig.fromHex("30440220" + "00".repeat(32) + "0220" + "00".repeat(32));

    /**
     * F-129: callStateful checks the preimage against the spending transaction
     * it builds from the compiled contract, so every call here passes the
     * honest preimage ({@code preimageFor}) built from the same spender-chosen
     * fields the test used to hand-roll.
     */
    private static final Path SOURCE = Path.of(
        "src", "main", "java", "runar", "examples", "tic-tac-toe",
        "TicTacToe.runar.java"
    );

    private static ContractSimulator simOf(TicTacToe g) {
        return ContractSimulator.stateful(g, SOURCE);
    }

    private TicTacToe freshGame() {
        // Constructor takes only the two readonly props (playerX +
        // betAmount); the remaining mutable fields default via
        // initialisers in the contract source.
        return new TicTacToe(ALICE, Bigint.of(1000));
    }

    /**
     * N-027: join requires {@code continuationAmount() == extractAmount(txPreimage) + betAmount}.
     * Off-chain {@code continuationAmount()} is fixed at 10000, so a paying join
     * is one whose input (the preimage amount, player X's bet) is 10000 - bet.
     */
    private static Preimage inputOf(long sats) {
        return Preimage.builder().amount(BigInteger.valueOf(sats)).build();
    }

    private static void joinPaying(ContractSimulator sim) {
        sim.callStateful("join", sim.preimageFor("join", inputOf(10000 - 1000), BOB, SIG), BOB, SIG);
    }

    @Test
    void joinActivatesGame() {
        TicTacToe g = freshGame();
        ContractSimulator sim = simOf(g);
        joinPaying(sim);
        assertEquals(BOB, g.playerO);
        assertEquals(Bigint.ONE, g.status);
        assertEquals(Bigint.ONE, g.turn);
    }

    @Test
    void moveFlipsTurn() {
        TicTacToe g = freshGame();
        ContractSimulator sim = simOf(g);
        joinPaying(sim);
        sim.call("move", Bigint.ZERO, ALICE, SIG); // turn was X (1), Alice plays cell 0
        assertEquals(Bigint.ONE, g.c0);
        assertEquals(Bigint.TWO, g.turn);
    }

    @Test
    void moveRejectsOccupiedCell() {
        TicTacToe g = freshGame();
        ContractSimulator sim = simOf(g);
        joinPaying(sim);
        sim.call("move", Bigint.ZERO, ALICE, SIG);
        // Bob tries to play on the occupied cell 0.
        assertThrows(AssertionError.class, () -> sim.call("move", Bigint.ZERO, BOB, SIG));
    }

    @Test
    void moveRejectsWrongPlayer() {
        TicTacToe g = freshGame();
        ContractSimulator sim = simOf(g);
        joinPaying(sim);
        // Turn is 1 (X = Alice), but Bob tries to move.
        assertThrows(AssertionError.class, () -> sim.call("move", Bigint.ZERO, BOB, SIG));
    }

    /**
     * N-027: a join must pay exactly the bet. An input of 10000 carried forward
     * unpaid (continuation 10000) passes F-024's {@code >= input} floor but not
     * join's rule, and neither does a continuation one satoshi short or over.
     */
    @Test
    void joinRejectsWrongPayment() {
        for (long input : new long[] {10000, 10000 - 1000 + 1, 10000 - 1000 - 1}) {
            TicTacToe g = freshGame();
            ContractSimulator sim = simOf(g);
            Preimage pre = sim.preimageFor("join", inputOf(input), BOB, SIG);
            AssertionError e = assertThrows(AssertionError.class, () -> sim.callStateful("join", pre, BOB, SIG),
                "join with input " + input + " must be rejected");
            assertFalse(String.valueOf(e.getMessage()).startsWith("checkPreimage"),
                "rejected by join's payment rule, not by the preimage check");
            assertEquals(Bigint.ZERO, g.status);
        }
    }

    /**
     * Runs the contract source through the Rúnar Java frontend
     * (parse → validate → typecheck).
     *
     * <p>Without this, the simulator tests above exercise the file only as
     * ordinary Java — javac compiles it, JUnit runs it, and nothing ever
     * asks a Rúnar compiler whether it is valid Rúnar. That is how the v2
     * sibling came to use four constructs no tier accepts while still
     * showing a green build.
     */
    @Test
    void contractCompiles() {
        Path source = Path.of(
            "src", "main", "java", "runar", "examples", "tic-tac-toe",
            "TicTacToe.runar.java"
        );
        assertDoesNotThrow(() -> CompileCheck.run(source));
    }
}

package runar.end2end;

import java.math.BigInteger;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.junit.jupiter.api.Test;
import runar.lang.runtime.ContractSimulator;
import runar.lang.sdk.CompileCheck;
import runar.lang.types.Bigint;
import runar.lang.types.ByteString;
import runar.lang.types.PubKey;
import runar.lang.types.RabinPubKey;
import runar.lang.types.RabinSig;
import runar.lang.types.Sig;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * End-to-end PriceBet tests. Mirrors the TypeScript / Go / Python /
 * Ruby / Rust / Zig PriceBet test suites under
 * {@code examples/end2end-example/}.
 *
 * <p>Two layers of coverage:
 *
 * <ol>
 *   <li>Business logic via {@link ContractSimulator} (mocked Rabin/ECDSA
 *       crypto — every branch of {@code settle} and {@code cancel} is
 *       exercised).</li>
 *   <li>Compiler frontend via {@link CompileCheck} (the contract parses,
 *       validates, and typechecks through the real Rúnar pipeline).</li>
 * </ol>
 *
 * <p>The on-chain (regtest) flow lives in {@code integration/java} —
 * the dedicated PriceBet regtest case can be added there once a
 * Rabin-aware {@code IntegrationWallet} helper lands; this file
 * intentionally stays node-free so {@code gradle test} works in any
 * environment, matching the Go {@code PriceBet_test.go} pattern.
 */
class PriceBetTest {

    // Mirrors the demo Rabin modulus used by the Python / Ruby end-to-end
    // tests; mock crypto inside ContractSimulator returns true regardless
    // of value, so the exact bytes don't matter — but using the same
    // 130-bit n keeps the tests visually consistent across languages.
    private static final RabinPubKey ORACLE_PK = new RabinPubKey(
        new BigInteger("950b36f00000000000000000000000002863620200000000000000000000000010", 16)
    );
    private static final RabinSig    ORACLE_SIG = new RabinSig(BigInteger.ONE);
    private static final ByteString  ORACLE_PADDING = ByteString.fromHex("00");

    private static final PubKey ALICE = PubKey.fromHex(
        "0202020202020202020202020202020202020202020202020202020202020202aa"
    );
    private static final PubKey BOB = PubKey.fromHex(
        "0303030303030303030303030303030303030303030303030303030303030303bb"
    );
    // 72-byte placeholder DER signatures — the simulator's checkSig is
    // mocked, so the bytes only have to be the right size.
    private static final Sig ALICE_SIG = Sig.fromHex("30440220" + "aa".repeat(32) + "0220" + "aa".repeat(32));
    private static final Sig BOB_SIG   = Sig.fromHex("30440220" + "bb".repeat(32) + "0220" + "bb".repeat(32));

    private static final Bigint STRIKE = Bigint.of(50_000);

    private static PriceBet makeBet() {
        return new PriceBet(ALICE, BOB, ORACLE_PK, STRIKE);
    }

    @Test
    void contractInstantiates() {
        PriceBet bet = makeBet();
        assertNotNull(bet);
    }

    @Test
    void settleAlicewinsWhenPriceExceedsStrike() {
        PriceBet bet = makeBet();
        ContractSimulator sim = ContractSimulator.stateless(bet);
        sim.call("settle",
            Bigint.of(60_000), ORACLE_SIG, ORACLE_PADDING,
            ALICE_SIG, BOB_SIG
        );
    }

    @Test
    void settleBobWinsWhenPriceBelowStrike() {
        PriceBet bet = makeBet();
        ContractSimulator sim = ContractSimulator.stateless(bet);
        sim.call("settle",
            Bigint.of(30_000), ORACLE_SIG, ORACLE_PADDING,
            ALICE_SIG, BOB_SIG
        );
    }

    @Test
    void settleBobWinsAtStrike() {
        // price == strike → bob wins (the contract's else branch).
        PriceBet bet = makeBet();
        ContractSimulator sim = ContractSimulator.stateless(bet);
        sim.call("settle",
            STRIKE, ORACLE_SIG, ORACLE_PADDING,
            ALICE_SIG, BOB_SIG
        );
    }

    @Test
    void settleRejectsZeroPrice() {
        PriceBet bet = makeBet();
        ContractSimulator sim = ContractSimulator.stateless(bet);
        assertThrows(AssertionError.class, () ->
            sim.call("settle",
                Bigint.of(0), ORACLE_SIG, ORACLE_PADDING,
                ALICE_SIG, BOB_SIG
            )
        );
    }

    @Test
    void cancelSucceedsWithBothSignatures() {
        PriceBet bet = makeBet();
        ContractSimulator sim = ContractSimulator.stateless(bet);
        sim.call("cancel", ALICE_SIG, BOB_SIG);
    }

    @Test
    void compileCheckPasses() throws Exception {
        // Run the contract through the real Rúnar frontend (parse +
        // validate + typecheck) and confirm it produces a valid
        // artifact. Mirrors the Go TestPriceBet_Compile case.
        Path source = Paths.get(System.getProperty("user.dir"))
            .resolve("src/main/java/runar/end2end/PriceBet.runar.java");
        CompileCheck.run(source);
    }
}

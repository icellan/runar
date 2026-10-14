package runar.examples.compilerdirectives;

import org.junit.jupiter.api.Test;
import runar.lang.annotations.EmbedAlways;
import runar.lang.annotations.Readonly;
import runar.lang.annotations.Sighash;
import runar.lang.runtime.ContractSimulator;
import runar.lang.runtime.MockCrypto;
import runar.lang.sdk.CompileCheck;
import runar.lang.types.Addr;
import runar.lang.types.ByteString;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/**
 * N-093 — the native Java spelling of the two compiler directives,
 * {@code @EmbedAlways} on {@code deployTag} and {@code @Sighash("SINGLE|FORKID")}
 * on {@code spendSingle}, in the Java port of
 * {@code examples/ts/compiler-directives/Directives.runar.ts}.
 *
 * <p>Proves: the contract compiles as ordinary Java against the runar-java
 * annotations (this source set would not build otherwise), the annotations
 * carry the declared values at runtime, both entry points run natively under
 * the off-chain simulator, and the source passes the Rúnar frontend. The
 * simulator mocks {@code checkSig}, so only the hash-mismatch failure is
 * on-chain-equivalent. Does NOT prove the compiled bytes or the sighash mode
 * the compiler records — the compiler tier's N093NativeDirectivesTest pins
 * those against the TypeScript reference.
 */
class DirectivesTest {

    private static final PubKey PK = PubKey.fromHex(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    );
    private static final Sig SIG = Sig.fromHex("30440220" + "00".repeat(32) + "0220" + "00".repeat(32));
    private static final ByteString TAG = ByteString.fromHex("cafe");

    @Test
    void annotationsCarryTheDeclaredDirectives() throws Exception {
        var deployTag = Directives.class.getDeclaredField("deployTag");
        assertTrue(deployTag.isAnnotationPresent(Readonly.class));
        assertTrue(deployTag.isAnnotationPresent(EmbedAlways.class));
        assertFalse(Directives.class.getDeclaredField("pubKeyHash").isAnnotationPresent(EmbedAlways.class));

        var spendSingle = Directives.class.getDeclaredMethod("spendSingle", Sig.class, PubKey.class);
        assertEquals("SINGLE|FORKID", spendSingle.getAnnotation(Sighash.class).value());
        var spendAll = Directives.class.getDeclaredMethod("spendAll", Sig.class, PubKey.class);
        assertNull(spendAll.getAnnotation(Sighash.class));
    }

    @Test
    void bothEntryPointsSucceedWithMatchingHash() {
        Directives c = new Directives(MockCrypto.hash160(PK), TAG);
        assertEquals(TAG, c.deployTag);
        ContractSimulator sim = ContractSimulator.stateless(c);
        assertDoesNotThrow(() -> sim.call("spendAll", SIG, PK));
        assertDoesNotThrow(() -> sim.call("spendSingle", SIG, PK));
    }

    @Test
    void bothEntryPointsFailWhenHashDoesNotMatch() {
        Directives c = new Directives(Addr.fromHex("00".repeat(20)), TAG);
        ContractSimulator sim = ContractSimulator.stateless(c);
        assertThrows(AssertionError.class, () -> sim.call("spendAll", SIG, PK));
        assertThrows(AssertionError.class, () -> sim.call("spendSingle", SIG, PK));
    }

    @Test
    void compilesThroughTheRunarFrontend() throws Exception {
        CompileCheck.run(Path.of("src/main/java/runar/examples/compiler-directives/Directives.runar.java"));
    }
}

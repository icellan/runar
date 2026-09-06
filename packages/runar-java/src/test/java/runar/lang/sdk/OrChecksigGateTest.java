package runar.lang.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.lang.reflect.Method;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * The issue #106 OR-CHECKSIG gate must recognise BOTH lowerings of {@code ||}.
 *
 * <p>It went blind once already: it tested for OP_BOOLOR, and NEW-014 stopped the
 * compiler emitting that opcode, so the NULLFAIL warning silently never fired.
 */
class OrChecksigGateTest {

    private static boolean gate(String asm) throws Exception {
        Method m = RunarContract.class.getDeclaredMethod("isLikelyOrChecksig", RunarArtifact.class);
        m.setAccessible(true);
        RunarArtifact.ABI abi = new RunarArtifact.ABI(
            new RunarArtifact.ABIConstructor(java.util.List.of()), java.util.List.of());
        RunarArtifact a = new RunarArtifact(
            "1", "1.0", "T", abi, "5100", asm, "", null, null, null, null, null);
        return (boolean) m.invoke(null, a);
    }

    @DisplayName("gate recognises both `||` lowerings, and excludes multi-sig")
    @ParameterizedTest(name = "{1} -> {0}")
    @CsvSource({
        "true,  'OP_DUP OP_BOOLOR OP_CHECKSIG'",
        "true,  'OP_IF OP_CHECKSIG OP_ELSE OP_CHECKSIG OP_ENDIF'",
        "false, 'OP_IF OP_CHECKSIG OP_CHECKMULTISIG'",
        "false, 'OP_IF OP_DUP OP_ELSE OP_DROP OP_ENDIF'",
        "false, 'OP_DUP OP_HASH160 OP_CHECKSIG'",
        "true,  'op_if op_checksig op_endif'",
        "false, ''",
    })
    void gateShape(boolean want, String asm) throws Exception {
        assertEquals(want, gate(asm), "asm=" + asm);
    }
}

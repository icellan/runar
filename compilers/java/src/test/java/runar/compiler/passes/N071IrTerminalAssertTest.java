package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import runar.compiler.ir.anf.AnfProgram;

/**
 * N-071 — the {@code --ir} loader refuses a public method that does not END
 * with an assert, with the diagnostic shared verbatim by all seven tiers.
 *
 * <p>Before: {@code "body": []} compiled to an EMPTY (anyone-can-spend)
 * locking script at exit 0, and an {@code if} whose else arm ended in
 * {@code load_const true} compiled to a script an empty signature spends.
 *
 * <p>Proves: each body shape below (the cases of
 * {@code conformance/negatives/ir-terminal-assert-cases.json}, inlined because
 * this tier's tests carry no JSON library) is refused with the exact shared
 * diagnostic, and the P2PK control and a both-arm {@code if} load. Does not
 * prove: that the other tiers agree
 * ({@code conformance/negatives/ir-terminal-assert.test.ts} does), or that an
 * accepted program is secure.
 */
class N071IrTerminalAssertTest {

    private static final String ERROR =
        "IR validation: public method 'unlock' must end with an assert() call (or an if/else"
        + " whose arms both do, or a terminal raw_script with out_arity 1); otherwise the value"
        + " its last binding leaves on the stack decides the spend";

    private static final String HEAD =
        "{\"name\":\"t0\",\"value\":{\"kind\":\"load_param\",\"name\":\"sig\"}},"
        + "{\"name\":\"t1\",\"value\":{\"kind\":\"load_prop\",\"name\":\"pk\"}},"
        + "{\"name\":\"t2\",\"value\":{\"kind\":\"call\",\"func\":\"checkSig\",\"args\":[\"t0\",\"t1\"]}}";

    private static final String ASSERT_T2 = "{\"name\":\"t3\",\"value\":{\"kind\":\"assert\",\"value\":\"t2\"}}";

    /** The N-069 P2PK control with the public method's body replaced. */
    private static String ir(String body) {
        return "{\"contractName\":\"X\",\"properties\":[{\"name\":\"pk\",\"type\":\"PubKey\",\"readonly\":true}],"
            + "\"methods\":[{\"name\":\"unlock\",\"isPublic\":true,"
            + "\"params\":[{\"name\":\"sig\",\"type\":\"Sig\"}],\"body\":[" + body + "]}]}";
    }

    @Test
    void controlLoads() {
        AnfProgram p = AnfLoader.parse(ir(HEAD + "," + ASSERT_T2));
        assertEquals("X", p.contractName());
    }

    @Test
    void ifWhoseArmsBothEndWithAnAssertLoads() {
        AnfLoader.parse(ir(HEAD + ",{\"name\":\"t3\",\"value\":{\"kind\":\"if\",\"cond\":\"t2\","
            + "\"then\":[{\"name\":\"t4\",\"value\":{\"kind\":\"assert\",\"value\":\"t2\"}}],"
            + "\"else\":[{\"name\":\"t5\",\"value\":{\"kind\":\"assert\",\"value\":\"t2\"}}]}}"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        // body-empty
        "",
        // body-without-assert
        "{\"name\":\"t0\",\"value\":{\"kind\":\"load_param\",\"name\":\"sig\"}}",
        // binding-after-last-assert
        HEAD + "," + ASSERT_T2 + ",{\"name\":\"t4\",\"value\":{\"kind\":\"load_const\",\"value\":true}}",
        // if-else-arm-without-assert
        HEAD + ",{\"name\":\"t3\",\"value\":{\"kind\":\"if\",\"cond\":\"t2\","
            + "\"then\":[{\"name\":\"t4\",\"value\":{\"kind\":\"assert\",\"value\":\"t2\"}}],"
            + "\"else\":[{\"name\":\"t5\",\"value\":{\"kind\":\"load_const\",\"value\":true}}]}}",
        // if-empty-else-arm
        HEAD + ",{\"name\":\"t3\",\"value\":{\"kind\":\"if\",\"cond\":\"t2\","
            + "\"then\":[{\"name\":\"t4\",\"value\":{\"kind\":\"assert\",\"value\":\"t2\"}}],\"else\":[]}}",
        // terminal-raw-script-out-arity-0
        HEAD + "," + ASSERT_T2
            + ",{\"name\":\"t4\",\"value\":{\"kind\":\"raw_script\",\"bytes\":\"61\",\"in_arity\":0,\"out_arity\":0}}",
    })
    void refusesWithSharedDiagnostic(String body) {
        RuntimeException ex = assertThrows(RuntimeException.class, () -> AnfLoader.parse(ir(body)));
        assertEquals(ERROR, ex.getMessage());
    }
}

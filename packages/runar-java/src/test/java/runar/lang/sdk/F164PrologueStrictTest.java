package runar.lang.sdk;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * F-164 (round 2): {@code executeStrict} must mock the WHOLE
 * auto-injected stateful prologue (checkPreimage's assert AND the
 * sighash-type assert), not just developer asserts.
 *
 * <p>See {@code packages/runar-sdk/src/anf-interpreter.ts} for the TS
 * reference this ports ({@code detectAutoInjectedPrologueAsserts} there,
 * {@code AnfInterpreter.detectAutoInjectedPrologueAsserts} here).
 *
 * <p>Round 1 of F-164 fixed the {@code check_preimage} ANF-node kind to
 * mock-return {@code true} in strict mode. That alone is NOT enough: the
 * compiler's prologue also emits a SECOND, un-marked assert right after —
 * the sighash-type check ({@code assert(extractSigHashType(txPreimage) ===
 * <mode>)}) — and {@code extractSigHashType} has no real/mock value
 * off-chain. Before round 2, a strict-mode call against a REAL compiled
 * stateful method would get past checkPreimage only to throw at the
 * sighash-type assert instead — never reaching the method's actual body.
 */
class F164PrologueStrictTest {

    @Test
    void executeStrictMocksWholeAutoInjectedPrologue() {
        // NOTE: deliberately hand-built (not loaded from the
        // `artifacts/stateful-counter.runar.json` test resource): that
        // fixture predates issue #123's sighash-type prologue check and
        // carries no `isAutoInjectedStateCheck` marker on its exit
        // continuation-hash assert either, so it fails for unrelated,
        // pre-existing reasons once round 1 of F-164 stops masking them at
        // checkPreimage. This body mirrors the CURRENT compiler's exact
        // 8-binding prologue shape (see fullPrologueAnf).
        Map<String, Object> anf = fullPrologueAnf(List.of(
            binding("t8", Map.of("kind", "load_prop", "name", "count")),
            binding("t9", Map.of("kind", "load_const", "value", BigInteger.ONE)),
            binding("t10", Map.of("kind", "bin_op", "op", "+", "left", "t8", "right", "t9")),
            binding("t11", Map.of("kind", "update_prop", "name", "count", "value", "t10"))
        ));

        AnfInterpreter.ExecutionResult result = AnfInterpreter.executeStrict(
            anf,
            "increment",
            Map.of("count", BigInteger.ZERO),
            Map.of(),
            List.of()
        );

        assertEquals(BigInteger.ONE, asBigInt(result.newState.get("count")));
    }

    @Test
    void userWrittenAssertAfterPrologueStillEnforced() {
        // Structural detection is anchored to bindings [0..7] at the START
        // of the method body — the compiler's own prologue. A developer's
        // own assert(extractSigHashType(txPreimage) === someMode), written
        // in their method body, is lowered AFTER the prologue and must
        // remain fully enforced in strict mode.
        Map<String, Object> anf = fullPrologueAnf(List.of(
            binding("u0", Map.of("kind", "load_param", "name", "txPreimage")),
            binding("u1", Map.of("kind", "call", "func", "extractSigHashType", "args", List.of("u0"))),
            binding("u2", Map.of("kind", "load_const", "value", BigInteger.ONE)), // wrong mode (real is 65)
            binding("u3", Map.of("kind", "bin_op", "op", "===", "left", "u1", "right", "u2")),
            binding("userAssert", Map.of("kind", "assert", "value", "u3")),
            binding("t8", Map.of("kind", "load_prop", "name", "count")),
            binding("t9", Map.of("kind", "load_const", "value", BigInteger.ONE)),
            binding("t10", Map.of("kind", "bin_op", "op", "+", "left", "t8", "right", "t9")),
            binding("t11", Map.of("kind", "update_prop", "name", "count", "value", "t10"))
        ));

        AnfInterpreter.AssertionFailureException ex = assertThrows(
            AnfInterpreter.AssertionFailureException.class,
            () -> AnfInterpreter.executeStrict(anf, "increment", Map.of("count", BigInteger.ZERO), Map.of(), List.of())
        );
        assertEquals("userAssert", ex.bindingName(),
            "mocking must not reach past the prologue");
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private static Map<String, Object> binding(String name, Map<String, Object> value) {
        return Map.of("name", name, "value", value);
    }

    /**
     * Hand-built ANF: the exact 8-binding prologue
     * {@code compilers/java/.../passes/AnfLower.java}'s stateful-prologue
     * emitter injects at the START of every public stateful method
     * (mirrors compiled conformance/tests/stateful-counter
     * expected-ir.json: t0-t7), followed by {@code tail}.
     */
    private static Map<String, Object> fullPrologueAnf(List<Map<String, Object>> tail) {
        java.util.List<Map<String, Object>> body = new java.util.ArrayList<>(List.of(
            binding("t0", Map.of("kind", "load_param", "name", "txPreimage")),
            binding("t1", Map.of("kind", "check_preimage", "preimage", "t0")),
            binding("t2", Map.of("kind", "assert", "value", "t1")),
            binding("t3", Map.of("kind", "load_param", "name", "txPreimage")),
            binding("t4", Map.of("kind", "call", "func", "extractSigHashType", "args", List.of("t3"))),
            binding("t5", Map.of("kind", "load_const", "value", BigInteger.valueOf(65))),
            binding("t6", Map.of("kind", "bin_op", "op", "===", "left", "t4", "right", "t5")),
            binding("t7", Map.of("kind", "assert", "value", "t6"))
        ));
        body.addAll(tail);
        return Map.of(
            "contractName", "Counter",
            "properties", List.of(Map.of("name", "count", "type", "bigint", "readonly", false)),
            "methods", List.of(Map.of(
                "name", "increment",
                "params", List.of(Map.of("name", "txPreimage", "type", "SigHashPreimage")),
                "body", body,
                "isPublic", true
            ))
        );
    }

    private static BigInteger asBigInt(Object v) {
        if (v instanceof BigInteger bi) return bi;
        if (v instanceof Number n) return BigInteger.valueOf(n.longValue());
        throw new IllegalArgumentException("not a BigInteger: " + v);
    }
}

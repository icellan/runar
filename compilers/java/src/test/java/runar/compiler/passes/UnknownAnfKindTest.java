package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import runar.compiler.ir.UnknownAnfKindError;
import runar.compiler.ir.anf.AnfBinding;
import runar.compiler.ir.anf.AnfMethod;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.anf.AnfValue;
import runar.compiler.ir.anf.BoolConst;
import runar.compiler.ir.anf.Call;
import runar.compiler.ir.anf.If;
import runar.compiler.ir.anf.LoadConst;
import runar.compiler.ir.anf.SyntheticAnfValueForTests;

/**
 * Regression test for F-003 (Java tier): every ANF-kind dispatch in the
 * Java compiler must throw {@link UnknownAnfKindError} when it
 * encounters a kind it doesn't recognize, instead of silently returning
 * an empty / no-op result.
 *
 * <p>Each test drives one dispatch site with a {@link SyntheticAnfValueForTests}
 * instance whose {@code kind()} does not appear in any production
 * dispatcher, then asserts the resulting throw is the typed error and
 * carries the synthetic kind name and a location string identifying the
 * dispatcher.
 *
 * <p>Mirrors {@code packages/runar-compiler/src/__tests__/unknown-anf-kind.test.ts}.
 *
 * <p>If a new {@link AnfValue} variant is added in the future, the
 * dispatch sites below must be updated; this test guards against
 * silently shipping an unhandled variant.
 */
class UnknownAnfKindTest {

    private static final String SYNTHETIC_KIND = "synthetic_test_kind_for_regression_only";

    private static AnfValue syntheticValue() {
        return SyntheticAnfValueForTests.of(SYNTHETIC_KIND);
    }

    private static AnfProgram makeProgram(List<AnfBinding> body) {
        AnfMethod method = new AnfMethod("m", List.of(), body, true);
        return new AnfProgram("Test", List.of(), List.of(method));
    }

    @Test
    void errorMessageReferencesDeveloperRecipe() {
        UnknownAnfKindError err = new UnknownAnfKindError(SYNTHETIC_KIND, "unit-test.location");
        assertTrue(err.getMessage().contains(SYNTHETIC_KIND),
            "message must contain the synthetic kind: " + err.getMessage());
        assertTrue(err.getMessage().contains("unit-test.location"),
            "message must contain the location: " + err.getMessage());
        assertTrue(err.getMessage().contains("Adding a New ANF Value Kind"),
            "message must reference the developer recipe: " + err.getMessage());
        assertEquals(SYNTHETIC_KIND, err.getKind());
        assertEquals("unit-test.location", err.getLocation());
    }

    @Test
    void throwsFromConstantFoldFoldValue() {
        AnfProgram program = makeProgram(List.of(
            new AnfBinding("t0", syntheticValue(), null)
        ));

        UnknownAnfKindError err = assertThrows(UnknownAnfKindError.class,
            () -> ConstantFold.run(program));
        assertEquals(SYNTHETIC_KIND, err.getKind());
        assertEquals("constant-fold.foldValue", err.getLocation());
    }

    @Test
    void throwsFromAnfOptimizeDispatchers() {
        // AnfOptimize.run is gated on the presence of an EC call (`ecAdd`,
        // `ecMul`, ...) — bodies with no EC primitives return unchanged and
        // never reach the dispatchers, by design. We seed the body with a
        // benign ecAdd call so the gate trips, then place the synthetic kind
        // in a sibling binding so renameInValue / collectRefs / hasSideEffect
        // walk over it and throw.
        AnfProgram program = makeProgram(List.of(
            new AnfBinding("ec0", new Call("ecAdd", List.of("a", "b")), null),
            new AnfBinding("t0", syntheticValue(), null)
        ));

        UnknownAnfKindError err = assertThrows(UnknownAnfKindError.class,
            () -> AnfOptimize.run(program));
        assertEquals(SYNTHETIC_KIND, err.getKind());
        assertTrue(
            err.getLocation().equals("anf-optimize.renameInValue")
                || err.getLocation().equals("anf-optimize.collectRefs")
                || err.getLocation().equals("anf-optimize.hasSideEffect"),
            "expected an anf-optimize dispatcher location, got " + err.getLocation());
    }

    @Test
    void throwsFromAnfLowerRemapValueRefs() {
        // remapValueRefs is package-private so we can drive it directly,
        // matching the TS test that calls remapValueRefs(synthetic, {}).
        UnknownAnfKindError err = assertThrows(UnknownAnfKindError.class,
            () -> AnfLower.remapValueRefs(syntheticValue(), new HashMap<>()));
        assertEquals(SYNTHETIC_KIND, err.getKind());
        assertEquals("anf-lower.remapValueRefs", err.getLocation());
    }

    @Test
    void throwsFromStackLower() {
        // collectRefs runs first inside StackLower.run (computeLastUses);
        // lowerBinding is the fallback path. Both are acceptable, matching
        // the TS test.
        AnfProgram program = makeProgram(List.of(
            new AnfBinding("t0", syntheticValue(), null)
        ));

        UnknownAnfKindError err = assertThrows(UnknownAnfKindError.class,
            () -> StackLower.run(program));
        assertEquals(SYNTHETIC_KIND, err.getKind());
        assertTrue(
            err.getLocation().equals("stack-lower.collectRefs")
                || err.getLocation().equals("stack-lower.lowerBinding"),
            "expected a stack-lower dispatcher location, got " + err.getLocation());
    }

    @Test
    void throwsFromAnfLoaderOnUnknownKindJson() {
        // The loader rejects unknown kinds at JSON decode time. Wrap the
        // synthetic kind inside a minimal well-formed AnfProgram JSON so
        // the parser walks from program -> method -> binding -> value and
        // hits the unknown-kind branch in toValue.
        String json = "{"
            + "\"contractName\":\"T\","
            + "\"properties\":[],"
            + "\"methods\":[{"
            +   "\"name\":\"m\",\"isPublic\":true,\"params\":[],"
            +   "\"body\":[{\"name\":\"t0\",\"value\":{\"kind\":\"" + SYNTHETIC_KIND + "\"}}]"
            + "}]"
            + "}";

        UnknownAnfKindError err = assertThrows(UnknownAnfKindError.class,
            () -> AnfLoader.parse(json));
        assertEquals(SYNTHETIC_KIND, err.getKind());
        assertEquals("anf-loader.parseValue", err.getLocation());
    }

    @Test
    void stackLowerCollectRefsExhaustsKnownKinds() {
        // Defensive: also confirm collectRefs is reached when the synthetic
        // value is nested under an `if`. The outer `if` is a known kind, so
        // the dispatcher must recurse into the then-branch and throw there.
        AnfProgram program = makeProgram(List.of(
            new AnfBinding("c", new LoadConst(new BoolConst(true)), null),
            new AnfBinding(
                "t0",
                new If(
                    "c",
                    List.of(new AnfBinding("tn", syntheticValue(), null)),
                    List.of()
                ),
                null
            )
        ));

        UnknownAnfKindError err = assertThrows(UnknownAnfKindError.class,
            () -> StackLower.run(program));
        assertEquals(SYNTHETIC_KIND, err.getKind());
        assertNotNull(err.getLocation());
        assertTrue(err.getLocation().startsWith("stack-lower."),
            "expected a stack-lower location, got " + err.getLocation());
    }
}

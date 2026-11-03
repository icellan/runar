package runar.compiler.frontend;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import org.junit.jupiter.api.Test;

/**
 * N-023 (R49) — on the .runar.java surface a bare name that no local or
 * parameter shadows IS the field, so {@code count = ...} writes contract
 * state in Java. The parser used to lower it as a local rebind: a stateful
 * contract compiled with no update_prop and its state never changed. Every
 * tier now refuses the bare form with the TS reference's diagnostic
 * ({@code bareJavaPropertyAssignmentMessage} in errors.ts).
 *
 * <p>What this proves: the Java tier's frontend refuses a bare property write
 * spelled {@code =}, {@code ++} / {@code --} (prefix, postfix, statement or
 * nested), inside an if arm or a for update, in any method including the
 * constructor, with the reference text; and it still accepts {@code this.x}
 * writes plus local, parameter and for-variable shadowing, honouring Java
 * block scope. Since N-130 lowers compound assignment, a bare
 * {@code count += ...} reaches this rule and gets the same diagnostic.
 *
 * <p>What it does NOT prove: the other tiers (their own suites and
 * conformance/negatives/N166), or anything about bare reads, which R49
 * leaves alone.
 */
class N023BarePropertyAssignTest {

    private static final String MSG =
        "bare assignment to property 'count' is not allowed; write `this.count = ...`";
    private static final String CTOR = "super(count);\n        this.count = count;";

    private static String src(String body, String params, String ctorParam, String ctorBody) {
        return "package p;\n"
            + "import runar.lang.StatefulSmartContract;\n"
            + "import runar.lang.annotations.Public;\n"
            + "import runar.lang.types.Bigint;\n"
            + "import static runar.lang.Builtins.assertThat;\n\n"
            + "class BareCounter extends StatefulSmartContract {\n"
            + "    Bigint count;\n\n"
            + "    BareCounter(Bigint " + ctorParam + ") {\n"
            + "        " + ctorBody + "\n"
            + "    }\n\n"
            + "    @Public\n"
            + "    void increment(" + params + ") {\n"
            + "        " + body + "\n"
            + "    }\n"
            + "}\n";
    }

    private static String refusal(String source) {
        try {
            ParserDispatch.parse(source, "BareCounter.runar.java");
        } catch (ParserDispatch.ParseException e) {
            return e.getMessage();
        }
        return null;
    }

    private static void assertRefusedWithMsg(String body, String source) {
        String got = refusal(source);
        if (got == null) fail("bare property write accepted: " + body);
        assertTrue(got.contains(MSG), body + ": expected '" + MSG + "', got: " + got);
    }

    @Test
    void bareAssignmentToAPropertyIsRefusedWithTheSharedDiagnostic() {
        String[] bodies = {
            "count = count.plus(Bigint.ONE);",
            "count++;",
            "--count;",
            "if (this.count.gt(Bigint.ZERO)) { count = Bigint.ONE; }",
            "for (Bigint i = Bigint.ZERO; i.lt(Bigint.TWO); count++) { assertThat(true); }",
            "assertThat((count++).gt(Bigint.ZERO));",
            "if (this.count.gt(Bigint.ZERO)) { Bigint count = Bigint.ONE; this.count = count; }\n        count = Bigint.TWO;",
            "count = Bigint.ONE;\n        Bigint count = Bigint.TWO;\n        this.count = count;",
        };
        for (String body : bodies) {
            assertRefusedWithMsg(body, src(body, "", "count", CTOR));
        }
        assertRefusedWithMsg("constructor",
            src("this.count = this.count.plus(Bigint.ONE);", "", "c", "super(c);\n        count = c;"));
        // Compound assignment (N-130 lowers it to `count = count + 1`).
        assertRefusedWithMsg("count += Bigint.ONE;", src("count += Bigint.ONE;", "", "count", CTOR));
    }

    @Test
    void shadowedOrExplicitAssignmentStillParses() {
        String[][] cases = {
            {"this.count = this.count.plus(Bigint.ONE);", ""},
            {"Bigint count = this.count;\n        count = count.plus(Bigint.ONE);\n        this.count = count;", ""},
            {"count = count.plus(Bigint.ONE);\n        this.count = count;", "Bigint count"},
            {"for (Bigint count = Bigint.ZERO; count.lt(Bigint.TWO); count++) { assertThat(true); }\n"
                + "        this.count = this.count.plus(Bigint.ONE);", ""},
            {"this.count = count.plus(Bigint.ONE);", ""},
        };
        for (String[] c : cases) {
            String got = refusal(src(c[0], c[1], "count", CTOR));
            if (got != null) fail("control refused: " + c[0] + " -> " + got);
        }
    }
}

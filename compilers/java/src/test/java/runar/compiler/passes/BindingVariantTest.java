package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.stack.StackProgram;

/**
 * Ports #170 (original design: brendan-elas, #167): the C=1 Any-S binding and
 * the {@code @bindingVariant} directive in the Java tier. The two blobs are
 * pinned here as literals so a Java-only drift fails this file; execution of
 * the same bytes through @bsv/sdk Spend lives in
 * packages/runar-testing/src/__tests__/binding-variant.test.ts.
 */
class BindingVariantTest {

    /** 422 bytes: s = lowS((z+1) mod n), C=1 key 038ff83d... */
    private static final String LOWS_HEX = "76aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937782927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad";
    /** 376 bytes: s = z+1, no mod-n, no low-S (nVersion != 1 only). */
    private static final String ALL_HEX = "76aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8b82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad";

    private static String counter(String directive) {
        return "class C extends StatefulSmartContract {\n"
            + "  count: bigint;\n"
            + "  constructor(count: bigint) { super(count); this.count = count; }\n"
            + "  " + directive + "\n"
            + "  public bump() { this.count++; }\n"
            + "}\n";
    }

    private static int count(String hay, String needle) {
        int n = 0;
        for (int i = hay.indexOf(needle); i != -1; i = hay.indexOf(needle, i + 1)) n++;
        return n;
    }

    private static String errorOf(String src, String file) {
        Exception e = assertThrows(Exception.class, () -> PipelineTestSupport.hex(src, file));
        return String.valueOf(e.getMessage());
    }

    @Test
    void pinnedSizes() {
        assertEquals(422, LOWS_HEX.length() / 2);
        assertEquals(376, ALL_HEX.length() / 2);
    }

    @Test
    void defaultAndExplicitLowSEmitTheC1Blob() throws Exception {
        for (String d : new String[] {"", "/** @bindingVariant lowS */"}) {
            String s = PipelineTestSupport.hex(counter(d), "C.runar.ts");
            assertEquals(1, count(s, LOWS_HEX), d);
            assertFalse(s.contains("02b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0"), d);
        }
    }

    @Test
    void allEmitsTheCompactBlob() throws Exception {
        String s = PipelineTestSupport.hex(counter("/** @bindingVariant all */"), "C.runar.ts");
        assertEquals(1, count(s, ALL_HEX));
        assertFalse(s.contains(LOWS_HEX));
    }

    @Test
    void nestedArmInherits() throws Exception {
        String src = "class G extends SmartContract {\n  constructor() { super(); }\n  /** @bindingVariant all */\n"
            + "  public unlock(a: SigHashPreimage, b: SigHashPreimage, c: boolean) {\n"
            + "    if (c) { assert(checkPreimage(a)); } else { assert(checkPreimage(b)); }\n  }\n}\n";
        String s = PipelineTestSupport.hex(src, "G.runar.ts");
        assertEquals(2, count(s, ALL_HEX));
        assertFalse(s.contains(LOWS_HEX));
    }

    @Test
    void directiveErrors() {
        String[][] cases = {
            {"/** @bindingVariant: all */",
                "@bindingVariant: malformed directive; expected `@bindingVariant lowS` or `@bindingVariant all`"},
            {"/** @bindingVariant high */", "@bindingVariant: unknown variant \"high\" (valid: lowS, all)"},
            {"/** @bindingVariant all */\n  // @bindingVariant lowS",
                "@bindingVariant: more than one @bindingVariant directive on this method; declare exactly one"},
        };
        for (String[] c : cases) {
            String e = errorOf(counter(c[0]), "C.runar.ts");
            assertTrue(e.contains(c[1]), c[0] + " -> " + e);
        }
        String priv = counter("/** @bindingVariant all */").replace("public bump", "private bump");
        String e = errorOf(priv, "C.runar.ts");
        assertTrue(e.contains("@bindingVariant directive on non-public method 'bump' has no effect"), e);
    }

    @Test
    void nonTsSurfacesRefuse() {
        String[][] surfaces = {
            {"C.runar.sol", "Solidity"}, {"C.runar.move", "Move"}, {"C.runar.py", "Python"}, {"C.runar.go", "Go DSL"},
            {"C.runar.rs", "Rust"}, {"C.runar.rb", "Ruby"}, {"C.runar.zig", "Zig"}, {"C.runar.java", "Java"},
        };
        for (String[] s : surfaces) {
            String want = "@bindingVariant directive is not supported by the " + s[1]
                + " surface parser; write the contract in TypeScript (.runar.ts), where @bindingVariant is honoured";
            String e = errorOf("// @bindingVariant all\n", s[0]);
            assertTrue(e.contains(want), s[0] + " -> " + e);
        }
    }

    @Test
    void irLoaderRefusesAnUnknownVariant() throws Exception {
        String json = PipelineTestSupport.anfJson(counter("/** @bindingVariant all */"), "C.runar.ts");
        assertTrue(json.contains("\"bindingVariant\":\"all\""), json);
        AnfProgram back = AnfLoader.parse(json);
        StackProgram stack = Peephole.run(StackLower.run(back));
        assertEquals(1, count(Emit.run(stack), ALL_HEX));
        String bad = json.replace("\"bindingVariant\":\"all\"", "\"bindingVariant\":\"high\"");
        Exception e = assertThrows(Exception.class, () -> AnfLoader.parse(bad));
        assertTrue(e.getMessage().contains("bindingVariant must be \"lowS\" or \"all\""), e.getMessage());
    }
}

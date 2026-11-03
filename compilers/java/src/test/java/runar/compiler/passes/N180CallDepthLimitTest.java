package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.frontend.InputLimits;
import runar.compiler.frontend.ParserDispatch;
import runar.compiler.ir.ast.ContractNode;

/**
 * N-180: the shared call-depth limit, MAX_CALL_DEPTH = 128.
 *
 * <p>A chain of private helpers {@code verify -> m0 -> m1 -> ... -> mN} is flat
 * source (MAX_SOURCE_NESTING never fires) but N+1 nested inlinings. Before N-180
 * this tier threw an uncaught {@code StackOverflowError} on an 8000-link chain
 * (and ran past 115 s of CPU at 2000 links): its recursion check restarted its
 * DFS from every method (quadratic) and recursed once per link.
 *
 * <p>Proves, on the .ts, .sol and .java surfaces (the last two call a helper as a
 * bare {@code m(x)}): the chain at the limit (N=127, verify at depth 128) passes
 * validation; one past (N=128) is refused with the shared diagnostic naming
 * {@code verify}; N=20000 is refused naming {@code m0}, promptly, with no
 * StackOverflowError; and a cycle is still the recursion diagnostic, once per
 * method that reaches it.
 *
 * <p>Does not prove: that the other surfaces agree, or that the accepted chain
 * compiles to the TS bytes (conformance/negatives/n180-call-depth-parity.test.ts
 * drives every CLI on all nine surfaces), nor anything about the --ir path.
 */
class N180CallDepthLimitTest {

    private static String diag(String m) {
        return "call depth of method '" + m + "' exceeds MAX_CALL_DEPTH (limit=128)";
    }

    private static String chain(String ext, int n) {
        StringBuilder b = new StringBuilder();
        switch (ext) {
            case "ts" -> {
                b.append("import { SmartContract, assert } from 'runar-lang';\nclass P extends SmartContract {\n readonly t: bigint;\n constructor(t: bigint) { super(t); this.t = t; }\n");
                for (int i = 0; i < n; i++) {
                    b.append(" private m").append(i).append("(x: bigint): bigint { return this.m").append(i + 1).append("(x); }\n");
                }
                b.append(" private m").append(n).append("(x: bigint): bigint { return x; }\n public verify(a: bigint) { assert(this.m0(a) == this.t); }\n}\n");
            }
            case "sol" -> {
                b.append("pragma runar ^0.1.0;\ncontract P is SmartContract {\n int immutable t;\n constructor(int _t) { t = _t; }\n");
                for (int i = 0; i < n; i++) {
                    b.append(" function m").append(i).append("(int x) private returns (int) { return m").append(i + 1).append("(x); }\n");
                }
                b.append(" function m").append(n).append("(int x) private returns (int) { return x; }\n function verify(int a) public { require(m0(a) == t); }\n}\n");
            }
            case "java" -> {
                b.append("package p;\n\nimport runar.lang.SmartContract;\nimport runar.lang.annotations.Public;\nimport runar.lang.annotations.Readonly;\nimport runar.lang.types.Bigint;\nimport static runar.lang.Builtins.assertThat;\n\nclass P extends SmartContract {\n    @Readonly Bigint t;\n    P(Bigint t) { super(t); this.t = t; }\n");
                for (int i = 0; i < n; i++) {
                    b.append("    private Bigint m").append(i).append("(Bigint x) { return m").append(i + 1).append("(x); }\n");
                }
                b.append("    private Bigint m").append(n).append("(Bigint x) { return x; }\n    @Public\n    void verify(Bigint a) { assertThat(m0(a).eq(this.t)); }\n}\n");
            }
            default -> throw new IllegalArgumentException(ext);
        }
        return b.toString();
    }

    private static List<String> errorsOf(String src, String fileName) throws Exception {
        ContractNode c = ParserDispatch.parse(src, fileName);
        return Validate.runCollecting(c).errors();
    }

    /** The one error, which must end with {@code want} (errors carry a file:line prefix). */
    private static void assertOnly(List<String> got, String want) {
        assertEquals(1, got.size(), () -> "want exactly [" + want + "], got " + got);
        assertTrue(got.get(0).endsWith(want), () -> "want [" + want + "], got " + got);
    }

    @Test
    void maxCallDepthIs128() {
        assertEquals(128, InputLimits.MAX_CALL_DEPTH);
    }

    @Test
    void chainBoundaryOnTsSolJava() throws Exception {
        for (String ext : List.of("ts", "sol", "java")) {
            String file = "P.runar." + ext;
            assertEquals(List.of(), errorsOf(chain(ext, 127), file), ext + ": N=127 must be accepted");
            assertOnly(errorsOf(chain(ext, 128), file), diag("verify"));
        }
    }

    @Test
    void chainOf20000IsRefusedPromptly() throws Exception {
        for (String ext : List.of("ts", "sol", "java")) {
            String src = chain(ext, 20000);
            long start = System.nanoTime();
            List<String> errs = errorsOf(src, "P.runar." + ext);
            long ms = (System.nanoTime() - start) / 1_000_000;
            assertOnly(errs, diag("m0"));
            assertTrue(ms < 60_000, ext + ": took " + ms + " ms (quadratic call-graph walk?)");
        }
    }

    @Test
    void cycleIsStillReportedAsRecursion() throws Exception {
        String src = "import { SmartContract, assert } from 'runar-lang';\nclass P extends SmartContract {\n readonly t: bigint;\n constructor(t: bigint) { super(t); this.t = t; }\n"
            + " private a(x: bigint): bigint { return this.b(x); }\n"
            + " private b(x: bigint): bigint { return this.c(x); }\n"
            + " private c(x: bigint): bigint { return this.b(x); }\n"
            + " private d(x: bigint): bigint { return x; }\n"
            + " public verify(v: bigint) { assert(this.a(v) + this.d(v) == this.t); }\n}\n";
        List<String> got = errorsOf(src, "P.runar.ts");
        List<String> names = List.of("a", "b", "c", "verify");
        assertEquals(names.size(), got.size(), () -> "got " + got);
        for (int i = 0; i < names.size(); i++) {
            assertTrue(
                got.get(i).endsWith("recursion detected: method '" + names.get(i) + "' calls itself directly or indirectly"),
                "got " + got);
        }
    }
}

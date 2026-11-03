package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import org.junit.jupiter.api.Test;
import runar.compiler.frontend.InputLimits;

/**
 * N-265 — the {@code --ir} path bypasses N-180's {@code MAX_CALL_DEPTH}
 * bound, and (outside Go's F-071, which was cycle-only) the recursion check
 * entirely.
 *
 * <p>{@link AnfLoader#parse} never ran the frontend's recursion/call-depth
 * check (that only runs on the source path). Stack lowering ({@code
 * StackLower}'s method_call inlining) inlines every method_call to a
 * private method by lowering its body in place, with no cycle or depth
 * guard, so a self/mutually-recursive method recurses the host call stack
 * until a {@link StackOverflowError}, and an acyclic chain past {@code
 * MAX_CALL_DEPTH} recurses it just as deep.
 *
 * <p>Proves: {@link AnfLoader#parse} now refuses a chain one past {@code
 * MAX_CALL_DEPTH}, naming the first offending method in declaration order
 * with the shared diagnostic, accepts a chain right at the bound, refuses a
 * 20000-link chain promptly (no {@link StackOverflowError}, no
 * multi-second hang), and refuses a direct/mutual cycle with the shared
 * recursion wording.
 *
 * <p>Does not prove: that the other six tiers' {@code --ir} loaders agree
 * ({@code conformance/negatives/n265-ir-call-depth-parity.test.ts} does);
 * call graphs other than a chain or a 2/3-node cycle; or that 128 is the
 * right number (N-180 already measured that).
 */
class N265IrCallDepthTest {

    /**
     * verify(a) calls m0(a); m_i calls m_{i+1} for i &lt; n; m_{n-1} returns
     * its argument unchanged. Declaration order is m0..m(n-1) THEN verify,
     * matching N-180's own chain fixture: at n=MAX_CALL_DEPTH only {@code
     * verify} exceeds the bound, but at n=20000 {@code m0} is declared
     * first and already exceeds it.
     */
    private static String chainIr(int n) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"contractName\":\"Chain\",\"properties\":[],\"methods\":[");
        for (int i = 0; i < n; i++) {
            if (i > 0) sb.append(',');
            if (i == n - 1) {
                sb.append("{\"name\":\"m").append(i).append("\",\"isPublic\":false,")
                  .append("\"params\":[{\"name\":\"x\",\"type\":\"bigint\"}],")
                  .append("\"body\":[{\"name\":\"t0\",\"value\":{\"kind\":\"load_param\",\"name\":\"x\"}}]}");
            } else {
                sb.append("{\"name\":\"m").append(i).append("\",\"isPublic\":false,")
                  .append("\"params\":[{\"name\":\"x\",\"type\":\"bigint\"}],")
                  .append("\"body\":[")
                  .append("{\"name\":\"t0\",\"value\":{\"kind\":\"load_const\",\"value\":\"@this\"}},")
                  .append("{\"name\":\"t1\",\"value\":{\"kind\":\"load_param\",\"name\":\"x\"}},")
                  .append("{\"name\":\"t2\",\"value\":{\"kind\":\"method_call\",\"object\":\"t0\",\"method\":\"m")
                  .append(i + 1).append("\",\"args\":[\"t1\"]}}")
                  .append("]}");
            }
        }
        if (n > 0) sb.append(',');
        sb.append("{\"name\":\"verify\",\"isPublic\":true,")
          .append("\"params\":[{\"name\":\"a\",\"type\":\"bigint\"}],")
          .append("\"body\":[")
          .append("{\"name\":\"t0\",\"value\":{\"kind\":\"load_const\",\"value\":\"@this\"}},")
          .append("{\"name\":\"t1\",\"value\":{\"kind\":\"load_param\",\"name\":\"a\"}},")
          .append("{\"name\":\"t2\",\"value\":{\"kind\":\"method_call\",\"object\":\"t0\",\"method\":\"m0\",\"args\":[\"t1\"]}},")
          .append("{\"name\":\"t3\",\"value\":{\"kind\":\"load_const\",\"value\":0}},")
          .append("{\"name\":\"t4\",\"value\":{\"kind\":\"bin_op\",\"op\":\">=\",\"left\":\"t2\",\"right\":\"t3\"}},")
          .append("{\"name\":\"t5\",\"value\":{\"kind\":\"assert\",\"value\":\"t4\"}}")
          .append("]}");
        sb.append("]}");
        return sb.toString();
    }

    /** unlock(x) calls private p(x); each pair is either a terminal (callee null, returns x) or forwards to callee. */
    private static String cycleIr(String[][] privateMethods) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"contractName\":\"Rec\",\"properties\":[],\"methods\":[")
          .append("{\"name\":\"unlock\",\"isPublic\":true,")
          .append("\"params\":[{\"name\":\"x\",\"type\":\"bigint\"}],")
          .append("\"body\":[")
          .append("{\"name\":\"t0\",\"value\":{\"kind\":\"load_const\",\"value\":\"@this\"}},")
          .append("{\"name\":\"t1\",\"value\":{\"kind\":\"load_param\",\"name\":\"x\"}},")
          .append("{\"name\":\"t2\",\"value\":{\"kind\":\"method_call\",\"object\":\"t0\",\"method\":\"p\",\"args\":[\"t1\"]}},")
          .append("{\"name\":\"t3\",\"value\":{\"kind\":\"load_const\",\"value\":0}},")
          .append("{\"name\":\"t4\",\"value\":{\"kind\":\"bin_op\",\"op\":\">=\",\"left\":\"t2\",\"right\":\"t3\"}},")
          .append("{\"name\":\"t5\",\"value\":{\"kind\":\"assert\",\"value\":\"t4\"}}")
          .append("]}");
        for (String[] pm : privateMethods) {
            String name = pm[0];
            String callee = pm[1];
            sb.append(',');
            if (callee == null) {
                sb.append("{\"name\":\"").append(name).append("\",\"isPublic\":false,")
                  .append("\"params\":[{\"name\":\"x\",\"type\":\"bigint\"}],")
                  .append("\"body\":[{\"name\":\"t0\",\"value\":{\"kind\":\"load_param\",\"name\":\"x\"}}]}");
            } else {
                sb.append("{\"name\":\"").append(name).append("\",\"isPublic\":false,")
                  .append("\"params\":[{\"name\":\"x\",\"type\":\"bigint\"}],")
                  .append("\"body\":[")
                  .append("{\"name\":\"t0\",\"value\":{\"kind\":\"load_const\",\"value\":\"@this\"}},")
                  .append("{\"name\":\"t1\",\"value\":{\"kind\":\"load_param\",\"name\":\"x\"}},")
                  .append("{\"name\":\"t2\",\"value\":{\"kind\":\"method_call\",\"object\":\"t0\",\"method\":\"").append(callee).append("\",\"args\":[\"t1\"]}}")
                  .append("]}");
            }
        }
        sb.append("]}");
        return sb.toString();
    }

    @Test
    void chainAtMaxCallDepthLoads() {
        assertDoesNotThrow(() -> AnfLoader.parse(chainIr(InputLimits.MAX_CALL_DEPTH)));
    }

    @Test
    void chainOnePastMaxCallDepthRefused() {
        RuntimeException e = assertThrows(RuntimeException.class,
            () -> AnfLoader.parse(chainIr(InputLimits.MAX_CALL_DEPTH + 1)));
        assertTrue(e.getMessage().contains(InputLimits.callDepthMessage("verify")), e.getMessage());
    }

    @Test
    void chain20000LinksRefusedPromptly() {
        long start = System.nanoTime();
        RuntimeException e = assertThrows(RuntimeException.class, () -> AnfLoader.parse(chainIr(20000)));
        assertTrue(e.getMessage().contains(InputLimits.callDepthMessage("m0")), e.getMessage());
        long elapsedMs = (System.nanoTime() - start) / 1_000_000;
        if (elapsedMs >= 10_000) fail("refusal took too long: " + elapsedMs + "ms");
    }

    @Test
    void directSelfRecursionRefused() {
        RuntimeException e = assertThrows(RuntimeException.class,
            () -> AnfLoader.parse(cycleIr(new String[][] {{"p", "p"}})));
        assertTrue(e.getMessage().contains("recursion detected"), e.getMessage());
        assertTrue(e.getMessage().contains("calls itself directly or indirectly"), e.getMessage());
        assertTrue(e.getMessage().contains("method 'p'"), e.getMessage());
    }

    @Test
    void mutualRecursionRefused() {
        RuntimeException e = assertThrows(RuntimeException.class,
            () -> AnfLoader.parse(cycleIr(new String[][] {{"p", "q"}, {"q", "p"}})));
        assertTrue(e.getMessage().contains("recursion detected"), e.getMessage());
        assertTrue(e.getMessage().contains("method 'p'") || e.getMessage().contains("method 'q'"), e.getMessage());
    }

    @Test
    void nonRecursiveChainStillLoads() {
        assertDoesNotThrow(() -> AnfLoader.parse(
            cycleIr(new String[][] {{"p", "q"}, {"q", "r"}, {"r", null}})));
    }
}

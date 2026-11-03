package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import runar.compiler.frontend.ParserDispatch;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.ir.ast.ExpressionStatement;
import runar.compiler.ir.ast.MethodNode;
import runar.compiler.ir.ast.Statement;
import runar.compiler.ir.ast.VariableDeclStatement;

/**
 * N-048 (external "PrematurePeek"): pass 3b hoists a computed FixedArray index
 * to {@code const __idx_K} in front of its whole statement. In
 *
 * <pre>assert(++this.cursor &gt; 0n &amp;&amp; this.enabled[this.cursor % 2n] === 1n);</pre>
 *
 * that bound the index BEFORE the increment, so the gate read the
 * pre-increment slot (an outsider spend at cursor 0 was accepted under the real
 * {@code @bsv/sdk} Spend). The AST has no let-expression, so every hoist that
 * would reorder evaluation is refused with the diagnostic shared by all seven
 * tiers.
 *
 * <p>Proves: the same refused / accepted shapes as the TS reference
 * ({@code packages/runar-compiler/src/__tests__/03b-expand-fixed-arrays.test.ts}).
 * Does not prove on-chain behaviour; the TS VM test and
 * {@code conformance/negatives/N120-N122} cover that across tiers.
 */
class N048FixedArrayIndexOrderTest {

    private static final String DIAG = "FixedArray index would be evaluated out of source order";

    private static final Map<String, String> REFUSED = Map.of(
        "the reported shape", "assert(++this.cursor > 0n && this.enabled[this.cursor % 2n] === 1n);",
        "index after an earlier ++", "assert(++this.cursor + this.enabled[this.cursor % 2n] > 0n);",
        "index after an output intrinsic", "assert(this.addRawOutput(1n, toByteString(\"00\")) === this.enabled[this.cursor % 2n]);",
        "right operand of &&", "assert(k > 0n && this.enabled[k - 1n] === 1n);",
        "right operand of ||", "assert(k === 0n || this.enabled[k - 1n] === 1n);",
        "ternary arm", "assert((c ? this.enabled[k + 1n] : 0n) === 0n);",
        "own ++ ahead of an earlier read", "assert(this.cursor + this.enabled[++this.cursor % 2n] > 0n);",
        "value read after target-index effect", "this.slots[++this.cursor % 2n] = this.enabled[this.cursor % 2n]; assert(true);"
    );

    private static final Map<String, String> ACCEPTED = Map.of(
        "increment in its own statement", "++this.cursor; assert(this.enabled[this.cursor % 2n] === 1n);",
        "left operand of &&", "assert(this.enabled[k - 1n] === 1n && k > 0n);",
        "ternary condition", "assert((this.enabled[k + 1n] === 1n ? 1n : 0n) === 1n);",
        "effect after the read", "assert(this.enabled[this.cursor % 2n] + ++this.cursor > 0n);",
        "statement-form read", "const v = this.enabled[k + 1n]; assert(v === 1n);",
        "computed write index, effectful value", "this.slots[this.cursor % 2n] = ++this.cursor; assert(true);"
    );

    private static ExpandFixedArrays.Result expand(String body) throws Exception {
        String src = "class Peek extends StatefulSmartContract {\n"
            + "  readonly enabled: FixedArray<bigint, 2> = [1n, 0n];\n"
            + "  slots: FixedArray<bigint, 2> = [0n, 0n];\n"
            + "  cursor: bigint;\n"
            + "  constructor(cursor: bigint) { super(cursor); this.cursor = cursor; }\n"
            + "  public release(k: bigint, c: boolean) {\n"
            + "    " + body + "\n"
            + "  }\n"
            + "}\n";
        ContractNode contract = ParserDispatch.parse(src, "Peek.runar.ts");
        return ExpandFixedArrays.runCollecting(contract);
    }

    private static String joined(ExpandFixedArrays.Result r) {
        return String.join("\n", r.errors());
    }

    @Test
    void refusesReorderingHoist() throws Exception {
        for (Map.Entry<String, String> c : REFUSED.entrySet()) {
            assertTrue(joined(expand(c.getValue())).contains(DIAG),
                c.getKey() + ": expected the hoist-order refusal");
        }
    }

    @Test
    void acceptsOrderPreservingHoist() throws Exception {
        for (Map.Entry<String, String> c : ACCEPTED.entrySet()) {
            String errs = joined(expand(c.getValue()));
            assertFalse(errs.contains(DIAG), c.getKey() + ": unexpected refusal " + errs);
        }
    }

    @Test
    void splitFormHoistsAfterIncrement() throws Exception {
        ExpandFixedArrays.Result r = expand("++this.cursor; assert(this.enabled[this.cursor % 2n] === 1n);");
        assertEquals(List.of(), r.errors());
        MethodNode m = r.contract().methods().stream()
            .filter(mm -> mm.name().equals("release")).findFirst().orElseThrow();
        List<Statement> body = m.body();
        assertInstanceOf(ExpressionStatement.class, body.get(0));
        VariableDeclStatement decl = assertInstanceOf(VariableDeclStatement.class, body.get(1));
        assertTrue(decl.name().startsWith("__idx_"), decl.name());
    }
}

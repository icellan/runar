package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.Cli;
import runar.compiler.frontend.JavaParser;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.ir.stack.StackProgram;

/**
 * N-158. The Java source map for the if-else conformance fixture did not
 * match the TS reference: OP_IF (opcode 11) had no mapping, and the arm-tail
 * merge ops (15/16 in the then arm, 21/22 in the else arm) were mapped to the
 * {@code if} line. Three causes: Peephole rebuilt the IfOp without its loc,
 * AnfLower stamped the {@code __merge$} result bindings with the enclosing
 * {@code if}'s location, and StackLower's branch sub-context inherited the
 * {@code if}'s location for ops no arm statement owns. TS leaves all of those
 * unlocated.
 *
 * The expected table is the TS reference map
 * (conformance/source-map/if-else/ts/expected-source-map.json) translated
 * statement for statement onto this file's lines: TS 12/13/14/16/18 are
 * Java 26/27/28/30/32 below.
 */
class N158IfElseSourceMapTest {

    // Same layout as examples/java/src/main/java/runar/examples/if-else/IfElse.runar.java.
    private static final String SRC = """
        package runar.examples.ifelse;

        import runar.lang.SmartContract;
        import runar.lang.annotations.Public;
        import runar.lang.annotations.Readonly;
        import runar.lang.types.Bigint;

        import static runar.lang.Builtins.assertThat;

        /**
         * IfElse -- exercises {@code if/else} branching with mutable local
         * variable assignment. The unlock requires the resulting value to be
         * positive after picking the addition or subtraction branch.
         */
        class IfElse extends SmartContract {

            @Readonly Bigint limit;

            IfElse(Bigint limit) {
                super(limit);
                this.limit = limit;
            }

            @Public
            void check(Bigint value, boolean mode) {
                Bigint result = Bigint.ZERO;
                if (mode) {
                    result = value.plus(this.limit);
                } else {
                    result = value.minus(this.limit);
                }
                assertThat(result.gt(Bigint.ZERO));
            }
        }
        """;

    /**
     * Proves: compiled through the same passes the CLI's --emit-source-map
     * uses (fold off, as conformance runs), the map is exactly the TS
     * reference's 14 entries: OP_IF at 11 is mapped to the {@code if}, and
     * 15/16/21/22 (arm merge ops) are unmapped.
     * Does not prove: other contract shapes (nested ifs, loops inside arms);
     * the six source-map fixtures are covered by conformance/source-map/run.ts.
     */
    @Test
    void ifElseMapMatchesTsReference() {
        ContractNode c = JavaParser.parse(SRC, "IfElse.runar.java");
        Validate.run(c);
        Typecheck.run(c);
        AnfProgram anf = Cli.optimizeAnf(AnfLower.run(c), true);
        StackProgram stack = Peephole.run(StackLower.run(anf));
        List<Emit.SourceMapping> map = Emit.runResultWithSourceMap(stack).sourceMap();

        List<String> got = new ArrayList<>();
        for (Emit.SourceMapping m : map) got.add(m.opcodeIndex() + "->" + m.line());

        List<String> want = List.of(
            "9->26",
            "10->27", "11->27",
            "12->28", "13->28", "14->28",
            "18->30", "19->30", "20->30",
            "24->27", "25->27", "26->27",
            "27->32", "28->32");
        assertEquals(want, got);
    }
}

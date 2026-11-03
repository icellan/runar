package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.frontend.JavaParser;
import runar.compiler.ir.anf.AnfBinding;
import runar.compiler.ir.anf.AnfMethod;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.anf.If;
import runar.compiler.ir.anf.UpdateProp;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.ir.stack.StackProgram;

/**
 * F-188. {@code AnfLower.liftBranchUpdateProps} rewrites a conditional
 * property update ({@code if (c) { this.x = a; } else { this.x = b; }}) into a
 * flat sequence of fresh bindings, and every one of them was built with a
 * literal {@code null} sourceLoc. Stack lowering can only stamp locations a
 * binding carries and {@code Emit} skips ops with none, so the opcodes that
 * implement the conditional state update were absent from the source map
 * (only the cond-setup opcodes the lift left alone were mapped).
 *
 * <p>Scheme under test: the synthesized per-branch {@code load_prop},
 * conditional {@code if} and {@code update_prop} carry the location of that
 * branch's original update statement; the shared condition temporaries
 * carry the original {@code if}'s location.
 */
class F188LiftedBranchUpdateSourceMapTest {

    private static final String SRC = """
        package runar.examples.sw;

        import runar.lang.StatefulSmartContract;
        import runar.lang.annotations.Public;
        import runar.lang.types.Bigint;

        class Sw extends StatefulSmartContract {

            Bigint x;

            Sw(Bigint x) {
                super(x);
                this.x = x;
            }

            @Public
            void set(Bigint flag, Bigint a, Bigint b) {
                if (flag.eq(Bigint.ZERO)) {
                    this.x = a;
                } else {
                    this.x = b;
                }
            }
        }
        """;

    private static int lineOf(String needle) {
        String[] lines = SRC.split("\n", -1);
        for (int i = 0; i < lines.length; i++) {
            if (lines[i].contains(needle)) return i + 1;
        }
        throw new AssertionError("no line containing " + needle);
    }

    private static AnfProgram lower() {
        ContractNode c = JavaParser.parse(SRC, "Sw.runar.java");
        Validate.run(c);
        Typecheck.run(c);
        return AnfLower.run(c);
    }

    /**
     * Proves: after the lift, the two synthesized {@code update_prop x}
     * bindings (and the conditional {@code if} feeding each) carry their
     * branch statement's line, and the lifted sequence reaches the emitted
     * source map with entries for both branch lines.
     *
     * Does not prove: the exact opcode indices of each entry, the
     * multi-branch (else-if chain / assert-false else) shapes beyond the
     * shared code path, or parity with other tiers (TS/Go/Rust/Python drop
     * these locations too).
     */
    @Test
    void liftedConditionalUpdateCarriesBranchLocationsIntoSourceMap() {
        int thenLine = lineOf("this.x = a;");
        int elseLine = lineOf("this.x = b;");

        AnfProgram anf = lower();
        AnfMethod set = anf.methods().stream()
            .filter(m -> m.name().equals("set")).findFirst().orElseThrow();

        List<AnfBinding> updates = new ArrayList<>();
        AnfBinding prev = null;
        List<AnfBinding> condIfs = new ArrayList<>();
        for (AnfBinding b : set.body()) {
            if (b.value() instanceof UpdateProp up && up.name().equals("x")) {
                updates.add(b);
                assertTrue(prev != null && prev.value() instanceof If,
                    "lifted update_prop must follow its conditional if");
                condIfs.add(prev);
            }
            prev = b;
        }
        assertEquals(2, updates.size(), "expected the two lifted update_prop x bindings");
        for (int i = 0; i < 2; i++) {
            int want = i == 0 ? thenLine : elseLine;
            assertNotNull(updates.get(i).sourceLoc(), "lifted update_prop " + i + " lost its sourceLoc");
            assertEquals(want, updates.get(i).sourceLoc().line());
            assertNotNull(condIfs.get(i).sourceLoc(), "lifted conditional if " + i + " lost its sourceLoc");
            assertEquals(want, condIfs.get(i).sourceLoc().line());
        }

        StackProgram stack = StackLower.run(anf);
        Emit.EmitResultFull full = Emit.runResultFull(stack);
        boolean sawThen = false;
        boolean sawElse = false;
        for (Emit.SourceMapping m : full.sourceMap()) {
            if (m.line() == thenLine) sawThen = true;
            if (m.line() == elseLine) sawElse = true;
        }
        assertTrue(sawThen, "no source-map entry for the then-branch update line " + thenLine);
        assertTrue(sawElse, "no source-map entry for the else-branch update line " + elseLine);
    }
}

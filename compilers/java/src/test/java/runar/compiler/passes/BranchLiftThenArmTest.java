package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import runar.compiler.frontend.ParserDispatch;
import runar.compiler.ir.anf.AnfBinding;
import runar.compiler.ir.anf.AnfMethod;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.anf.AnfValue;
import runar.compiler.ir.anf.BytesConst;
import runar.compiler.ir.anf.If;
import runar.compiler.ir.anf.LoadConst;
import runar.compiler.ir.anf.LoadProp;
import runar.compiler.ir.anf.UpdateProp;
import runar.compiler.ir.ast.ContractNode;

/**
 * Regression test: the branch-lift must not zero the matched arm.
 *
 * <p>{@code AnfLower.liftBranchUpdateProps} flattens a dispatch chain
 *
 * <pre>
 *   if (p == 0n) { this.c0 = v; } else if (p == 1n) { this.c1 = v; }
 *   else { assert(false); }
 * </pre>
 *
 * into one single-valued {@code if} per property plus a top-level
 * {@code update_prop}. The {@code if}'s then-arm must evaluate to the assigned
 * value and its else-arm to the property's old value.
 *
 * <p>The defect: the then-arm was built from {@code branch.valueBindings} —
 * everything BEFORE the {@code update_prop} in the original arm. That ends on
 * the assigned value only when the value was computed INSIDE the arm. When the
 * arm assigns something bound outside it, {@code valueBindings} is empty, the
 * arm was emitted EMPTY, and stack lowering padded it with a zero push
 * ({@code OP_IF OP_0 OP_ELSE OP_DUP OP_ENDIF}): the MATCHED branch wrote 0.
 *
 * <p>{@code examples/ts/tic-tac-toe} escapes it only because
 * {@code this.cN = this.turn} puts a {@code load_prop} inside the arm — that
 * shape is the control below.
 */
class BranchLiftThenArmTest {

    private static final String LOCAL_VALUE_DISPATCH = """
        class LocalValueDispatch extends StatefulSmartContract {
          c0: bigint;
          c1: bigint;

          constructor(c0: bigint, c1: bigint) {
            super(c0, c1);
            this.c0 = c0;
            this.c1 = c1;
          }

          public poke(position: bigint, value: bigint) {
            const doubled: bigint = value + value;
            if (position == 0n) { this.c0 = doubled; }
            else if (position == 1n) { this.c1 = doubled; }
            else { assert(false); }
          }
        }
        """;

    private static final String IN_ARM_VALUE_DISPATCH = """
        class InArmValueDispatch extends StatefulSmartContract {
          c0: bigint;
          c1: bigint;
          turn: bigint;

          constructor(c0: bigint, c1: bigint, turn: bigint) {
            super(c0, c1, turn);
            this.c0 = c0;
            this.c1 = c1;
            this.turn = turn;
          }

          public poke(position: bigint) {
            if (position == 0n) { this.c0 = this.turn; }
            else if (position == 1n) { this.c1 = this.turn; }
            else { assert(false); }
          }
        }
        """;

    private record Lifted(String prop, List<AnfBinding> then, List<AnfBinding> elseArm) {}

    /**
     * Every top-level {@code update_prop} whose value is an {@code if} binding,
     * paired with that {@code if}'s two arms.
     */
    private static List<Lifted> liftedAssignments(String source, String file) throws Exception {
        ContractNode contract = ParserDispatch.parse(source, file);
        AnfProgram prog = AnfLower.run(contract);

        AnfMethod method = null;
        for (AnfMethod m : prog.methods()) {
            if (m.name().equals("poke")) {
                method = m;
                break;
            }
        }
        assertTrue(method != null, "method poke not found in lowered program");

        Map<String, AnfValue> byName = new HashMap<>();
        for (AnfBinding b : method.body()) byName.put(b.name(), b.value());

        List<Lifted> out = new ArrayList<>();
        for (AnfBinding b : method.body()) {
            if (!(b.value() instanceof UpdateProp up)) continue;
            AnfValue producer = byName.get(up.value());
            if (!(producer instanceof If iff)) continue;
            out.add(new Lifted(up.name(), iff.thenBranch(), iff.elseBranch()));
        }
        return out;
    }

    @Test
    void thenArmCarriesValueBoundOutsideTheArm() throws Exception {
        List<Lifted> lifted = liftedAssignments(LOCAL_VALUE_DISPATCH, "LocalValueDispatch.runar.ts");

        // Both properties in the chain must be lifted. If this is 0 the pass has
        // stopped recognising the shape and the arm assertions below would pass
        // vacuously.
        assertEquals(2, lifted.size(), "expected 2 lifted conditional assignments");

        for (Lifted l : lifted) {
            assertFalse(l.then().isEmpty(),
                "then-arm for this." + l.prop() + " is empty; stack lowering pads it with OP_0, "
                + "so the MATCHED branch writes zero instead of the assigned value");
            AnfBinding last = l.then().get(l.then().size() - 1);
            LoadConst lc = assertInstanceOf(LoadConst.class, last.value(),
                "then-arm for this." + l.prop() + " must end on the assigned local");
            BytesConst bc = assertInstanceOf(BytesConst.class, lc.value());
            assertEquals("@ref:doubled", bc.hex(),
                "then-arm for this." + l.prop() + " must end on the assigned local");
            assertFalse(l.elseArm().isEmpty(), "else-arm for this." + l.prop() + " is empty");
        }
    }

    /**
     * Control: the TicTacToe shape already computed its value inside the arm and
     * was always correct. The fix must add nothing here — a second binding would
     * move the checked-in goldens.
     */
    @Test
    void inArmValueShapeIsUnchanged() throws Exception {
        List<Lifted> lifted = liftedAssignments(IN_ARM_VALUE_DISPATCH, "InArmValueDispatch.runar.ts");

        assertEquals(2, lifted.size(), "expected 2 lifted conditional assignments");
        for (Lifted l : lifted) {
            assertEquals(1, l.then().size(),
                "then-arm for this." + l.prop() + " should hold exactly the in-arm load_prop");
            LoadProp lp = assertInstanceOf(LoadProp.class, l.then().get(0).value());
            assertEquals("turn", lp.name());
        }
    }
}

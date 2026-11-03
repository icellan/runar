package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import org.junit.jupiter.api.Test;
import runar.compiler.Cli;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.stack.StackProgram;

/**
 * F-072 &mdash; lowerCall's {@code exit} / {@code assert} branches recorded a
 * stack slot no opcode produces.
 *
 * <p>{@code exit(cond)} lowers as {@code call exit} (no dedicated ANF node);
 * stack lowering ran {@code cond OP_VERIFY} and then pushed a slot for the
 * void result. OP_VERIFY leaves nothing behind, so every later PICK/ROLL
 * addressed the item one below the one it meant. For
 * {@code check(b, a, x, y) { exit(x > 0n); assert(y === 1n); assert(a > 5n); assert(b === 0n); }}
 * every tier emitted {@code 7c00a0697c519d7c55a0697c9177}, which the
 * five-push witness (0, b=6, a=1, x=1, y=999) spends. {@code call assert}
 * (reachable only through --ir) hit the same bug; the {@code super} branch is
 * dead (constructors are never stack-lowered and the loader refuses
 * {@code super} elsewhere).
 *
 * <p>What this proves: the Java tier emits the hand-derived
 * {@code 7c00a069519d55a06991} on the source path (both fold modes) and on the
 * --ir path (loader + the CLI's IR optimisation) for {@code call exit} and
 * {@code call assert}. What it does NOT prove: that the script spends
 * correctly &mdash; executed on the @bsv/sdk engine for all seven tiers in
 * packages/runar-testing/src/__tests__/f072-exit-phantom-slot-spend.test.ts.
 */
class F072ExitPhantomSlotTest {

    private static final String EXPECTED = "7c00a069519d55a06991";
    private static final String PRE_FIX = "7c00a0697c519d7c55a0697c9177";

    private static final String SOURCE = """
        import { SmartContract, assert } from 'runar-lang';

        class ExitAssert4 extends SmartContract {
          constructor() {
            super();
          }

          public check(b: bigint, a: bigint, x: bigint, y: bigint) {
            exit(x > 0n);
            assert(y === 1n);
            assert(a > 5n);
            assert(b === 0n);
          }
        }
        """;

    private static String ir(String guard) {
        return """
            {"contractName": "ExitAssert4", "properties": [], "methods": [
              {"name": "constructor", "isPublic": false, "params": [], "body": [
                {"name": "t0", "value": {"kind": "call", "func": "super", "args": []}}]},
              {"name": "check", "isPublic": true, "params": [
                {"name": "b", "type": "bigint"}, {"name": "a", "type": "bigint"},
                {"name": "x", "type": "bigint"}, {"name": "y", "type": "bigint"}], "body": [
                {"name": "t0", "value": {"kind": "load_param", "name": "x"}},
                {"name": "t1", "value": {"kind": "load_const", "value": 0}},
                {"name": "t2", "value": {"kind": "bin_op", "op": ">", "left": "t0", "right": "t1"}},
                {"name": "t3", "value": {"kind": "call", "func": "%s", "args": ["t2"]}},
                {"name": "t4", "value": {"kind": "load_param", "name": "y"}},
                {"name": "t5", "value": {"kind": "load_const", "value": 1}},
                {"name": "t6", "value": {"kind": "bin_op", "op": "===", "left": "t4", "right": "t5"}},
                {"name": "t7", "value": {"kind": "assert", "value": "t6"}},
                {"name": "t8", "value": {"kind": "load_param", "name": "a"}},
                {"name": "t9", "value": {"kind": "load_const", "value": 5}},
                {"name": "t10", "value": {"kind": "bin_op", "op": ">", "left": "t8", "right": "t9"}},
                {"name": "t11", "value": {"kind": "assert", "value": "t10"}},
                {"name": "t12", "value": {"kind": "load_param", "name": "b"}},
                {"name": "t13", "value": {"kind": "load_const", "value": 0}},
                {"name": "t14", "value": {"kind": "bin_op", "op": "===", "left": "t12", "right": "t13"}},
                {"name": "t15", "value": {"kind": "assert", "value": "t14"}}]}]}
            """.formatted(guard);
    }

    @Test
    void exitThenAssertSourceReadsTheRightSlots() throws Exception {
        for (boolean disableFold : new boolean[] {true, false}) {
            String hex = PipelineTestSupport.hex(SOURCE, "ExitAssert4.runar.ts", disableFold);
            assertNotEquals(PRE_FIX, hex, "phantom slot after exit() (disableFold=" + disableFold + ")");
            assertEquals(EXPECTED, hex, "disableFold=" + disableFold);
        }
    }

    @Test
    void callExitAndCallAssertIrReadTheRightSlots() {
        for (String guard : new String[] {"exit", "assert"}) {
            AnfProgram anf = Cli.optimizeAnf(AnfLoader.parse(ir(guard)), true);
            StackProgram stack = Peephole.run(StackLower.run(anf));
            assertEquals(EXPECTED, Emit.run(stack), "call " + guard);
        }
    }
}

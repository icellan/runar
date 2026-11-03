package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import org.junit.jupiter.api.Test;

/**
 * N-005 — an assert that is not the method's last binding must be lowered
 * with OP_VERIFY. Port of the reference tier's case in
 * {@code packages/runar-compiler/src/__tests__/asm-surface.test.ts}.
 *
 * <p>Stack lowering treated the LAST assert of a public method as terminal
 * (its value left as the script result) even when a terminal asm() followed
 * it. The asm pushed OP_1, the end-of-method cleanup NIPped the comparison
 * away, and the method compiled to 012a9c5177 (&lt;42&gt; OP_NUMEQUAL OP_1
 * OP_NIP): spendable with ANY x. The hand-derived fixed script is 012a9d51
 * (&lt;42&gt; OP_NUMEQUALVERIFY OP_1).
 *
 * <p>Proves: this tier's bytes for the shape in both fold modes, and that a
 * truly final assert still stays the method result. Does NOT prove on-chain
 * behaviour — the Spend-engine proof for all seven tiers is
 * {@code packages/runar-testing/src/__tests__/n005-assert-then-asm-spend.test.ts}.
 */
class N005AssertThenAsmTest {

    private static final String ASSERT_THEN_ASM =
        "import { UnsafeSmartContract, assert, asm } from 'runar-lang';\n\n"
            + "class AssertThenAsm extends UnsafeSmartContract {\n"
            + "  constructor() {\n"
            + "    super();\n"
            + "  }\n\n"
            + "  public unlock(x: bigint) {\n"
            + "    assert(x === 42n);\n"
            + "    asm({ body: '51', in_arity: 0, out_arity: 1 });\n"
            + "  }\n"
            + "}\n";

    private static final String ASM_THEN_ASSERT =
        "import { UnsafeSmartContract, assert, asm } from 'runar-lang';\n\n"
            + "class AsmThenAssert extends UnsafeSmartContract {\n"
            + "  constructor() {\n"
            + "    super();\n"
            + "  }\n\n"
            + "  public unlock(x: bigint) {\n"
            + "    asm({ body: '51', in_arity: 0, out_arity: 1 });\n"
            + "    assert(x === 42n);\n"
            + "  }\n"
            + "}\n";

    @Test
    void assertBeforeTerminalAsmIsVerified() throws Exception {
        for (boolean disable : new boolean[] {true, false}) {
            String got = PipelineTestSupport.hex(ASSERT_THEN_ASM, "AssertThenAsm.runar.ts", disable);
            assertNotEquals("012a9c5177", got, "disable_fold=" + disable + ": assert left unenforced");
            assertEquals("012a9d51", got, "disable_fold=" + disable + ": want <42> OP_NUMEQUALVERIFY OP_1");
        }
    }

    @Test
    void finalAssertStaysTheResult() throws Exception {
        // OP_1 OP_SWAP <42> OP_NUMEQUAL (terminal, no OP_VERIFY) OP_NIP
        assertEquals("517c012a9c77", PipelineTestSupport.hex(ASM_THEN_ASSERT, "AssertThenAsm.runar.ts", true));
    }
}

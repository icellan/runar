package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.ir.ast.CallExpr;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.ir.ast.MethodNode;
import runar.compiler.ir.ast.Statement;
import runar.compiler.ir.ast.VariableDeclStatement;

/**
 * R-025 / R-026 — {@link ExpandFixedArrays} must not drop AST node fields.
 *
 * <p>{@code rewriteMethod} and the {@code CallExpr} reconstructions each called
 * a backwards-compatible convenience constructor that omits the last field, so
 * two fields silently reverted to their defaults for any contract that also
 * declares a FixedArray property:
 *
 * <ul>
 *   <li>{@code MethodNode.sighashType} — a contract declaring
 *       {@code @sighash SINGLE|FORKID} compiled as if it had declared the
 *       default {@code ALL|FORKID} (0x41). Validation has already ACCEPTED the
 *       non-default mode by the time this pass runs, so the author gets a
 *       different signature-hash commitment than they wrote, with no
 *       diagnostic.
 *   <li>{@code CallExpr.asmReturnType} — an expression-form
 *       {@code asm<ByteString>()} lost its byte tag, so {@code +} lowered to
 *       OP_ADD instead of OP_CAT.
 * </ul>
 *
 * <p>Each case is paired with the SAME contract minus the FixedArray property,
 * so the control isolates the expansion path as the cause.
 */
class R025FieldPreservationTest {

    private static final int SINGLE_FORKID = 0x43;
    private static final String ARRAY_PROP = "  board: FixedArray<bigint, 3> = [0n, 0n, 0n];\n";

    // ------------------------------------------------------------------
    // MethodNode.sighashType
    // ------------------------------------------------------------------

    private static String sighashSrc(String directive, String arrayProp) {
        // A mutate-only continuation is rejected under SINGLE (rule F1), so the
        // body emits an explicit addOutput -- the shape a real pairwise
        // covenant uses. The array slots ride along in the continuation state.
        String values = arrayProp.isEmpty()
            ? ""
            : "this.board[0], this.board[1], this.board[2], ";
        return "class Boardy extends StatefulSmartContract {\n"
            + arrayProp
            + "  n: bigint;\n"
            + "  constructor(n: bigint) { super(n); this.n = n; }\n"
            + "  " + directive + "\n"
            + "  public bump(): void { this.addOutput(1000n, " + values + "this.n); }\n"
            + "}\n";
    }

    @Test
    void sighashTypeSurvivesRewriteMethod() throws Exception {
        ContractNode contract = PipelineTestSupport.parseValidated(
            sighashSrc("/** @sighash SINGLE|FORKID */", ARRAY_PROP), "Boardy.runar.ts");
        assertEquals(SINGLE_FORKID, methodNamed(contract, "bump").sighashType());

        ContractNode expanded = ExpandFixedArrays.run(contract);
        assertEquals(
            SINGLE_FORKID,
            methodNamed(expanded, "bump").sighashType(),
            "ExpandFixedArrays dropped MethodNode.sighashType");
    }

    @Test
    void emittedFlagIsTheDeclaredMode() throws Exception {
        String hex = PipelineTestSupport.hex(
            sighashSrc("/** @sighash SINGLE|FORKID */", ARRAY_PROP), "Boardy.runar.ts");
        assertTrue(hex.contains("0143"),
            "emitted script pins the DEFAULT 0x41, not the declared 0x43");
        assertFalse(hex.contains("0141"), "default flag byte must not survive");
    }

    @Test
    void controlWithoutFixedArrayIsUnchanged() throws Exception {
        String hex = PipelineTestSupport.hex(
            sighashSrc("/** @sighash SINGLE|FORKID */", ""), "Boardy.runar.ts");
        assertTrue(hex.contains("0143"));
        assertFalse(hex.contains("0141"));
    }

    @Test
    void defaultModeStillPins0x41() throws Exception {
        String hex = PipelineTestSupport.hex(sighashSrc("", ARRAY_PROP), "Boardy.runar.ts");
        assertTrue(hex.contains("0141"));
    }

    // ------------------------------------------------------------------
    // R-075 — the assertions that bind the on-chain commitment
    // ------------------------------------------------------------------

    /**
     * R-075: {@code emittedFlagIsTheDeclaredMode} greps the final hex for
     * {@code 0143}, which cannot tell the BIP-143 binding flag apart from any
     * other two-byte push that happens to be 0x43. This pins the node that
     * actually carries the commitment — the ANF {@code check_preimage}, which
     * is what StackLower reads and what the SDK mirrors when it builds the
     * preimage off-chain.
     */
    @Test
    void anfCheckPreimageCarriesDeclaredFlagWithFixedArray() throws Exception {
        String anf = PipelineTestSupport.anfJson(
            sighashSrc("/** @sighash SINGLE|FORKID */", ARRAY_PROP), "Boardy.runar.ts");
        assertTrue(anf.contains("\"sighashFlag\":" + SINGLE_FORKID),
            "ANF check_preimage lost the declared 0x43 across FixedArray expansion: " + anf);
    }

    /** Control: no directive + FixedArray — the key is absent entirely. */
    @Test
    void anfDefaultOmitsSighashFlagWithFixedArray() throws Exception {
        String anf = PipelineTestSupport.anfJson(sighashSrc("", ARRAY_PROP), "Boardy.runar.ts");
        assertFalse(anf.contains("sighashFlag"),
            "default must omit sighashFlag (byte-identical to the pinned mode): " + anf);
    }

    /** Control: the same directive with NO FixedArray never reaches the rewrite. */
    @Test
    void anfControlWithoutFixedArrayCarriesDeclaredFlag() throws Exception {
        String anf = PipelineTestSupport.anfJson(
            sighashSrc("/** @sighash SINGLE|FORKID */", ""), "Boardy.runar.ts");
        assertTrue(anf.contains("\"sighashFlag\":" + SINGLE_FORKID), anf);
    }

    /**
     * R-075, byte-exact: on a FixedArray contract the declared SINGLE|FORKID
     * script must differ from the default-mode script at EXACTLY two offsets —
     * the OP_PUSH_TX binding flag and the auto-injected preimage-type assert
     * const — each 0x41 -&gt; 0x43. Under the drop the two scripts are
     * byte-IDENTICAL, so a zero-difference result is the failure mode this
     * guards. Stronger than a whole-script hash: it survives unrelated codegen
     * churn but still fails the moment the mode stops reaching the emitter.
     */
    @Test
    void fixedArraySingleDiffersFromDefaultAtExactlyTheTwoSighashBytes() throws Exception {
        String single = PipelineTestSupport.hex(
            sighashSrc("/** @sighash SINGLE|FORKID */", ARRAY_PROP), "Boardy.runar.ts");
        String dflt = PipelineTestSupport.hex(sighashSrc("", ARRAY_PROP), "Boardy.runar.ts");
        assertEquals(dflt.length(), single.length(), "sighash mode must not resize the script");

        List<Integer> moved = new ArrayList<>();
        for (int i = 0; i + 1 < single.length(); i += 2) {
            String s = single.substring(i, i + 2);
            String d = dflt.substring(i, i + 2);
            if (!s.equals(d)) {
                assertEquals("41", d, "unexpected byte change at " + (i / 2));
                assertEquals("43", s, "unexpected byte change at " + (i / 2));
                moved.add(i / 2);
            }
        }
        assertEquals(List.of(388, 516), moved,
            "expected exactly the two 0x41->0x43 sighash bytes; got " + moved);
    }

    // ------------------------------------------------------------------
    // CallExpr.asmReturnType
    // ------------------------------------------------------------------

    private static final String ASM_ARRAY_PROP =
        "  readonly board: FixedArray<bigint, 3> = [1n, 2n, 3n];\n";

    private static String asmSrc(String arrayProp) {
        String tail = arrayProp.isEmpty()
            ? "    assert(this.n === this.n);\n"
            : "    assert(this.board[0] === this.n);\n";
        return "class Boardy extends UnsafeSmartContract {\n"
            + arrayProp
            + "  readonly n: bigint;\n"
            + "  constructor(n: bigint) { super(n); this.n = n; }\n"
            + "  public go(): void {\n"
            + "    const a: ByteString = asm<ByteString>"
            + "({ body: '00', in_arity: 0, out_arity: 1 });\n"
            + "    const c: ByteString = a + a;\n"
            + "    assert(len(c) === 2n);\n"
            + tail
            + "  }\n"
            + "}\n";
    }

    @Test
    void asmReturnTypeSurvivesRewriteExpression() throws Exception {
        ContractNode contract =
            PipelineTestSupport.parseValidated(asmSrc(ASM_ARRAY_PROP), "Boardy.runar.ts");
        ContractNode expanded = ExpandFixedArrays.run(contract);

        Statement first = methodNamed(expanded, "go").body().get(0);
        VariableDeclStatement decl = (VariableDeclStatement) first;
        assertEquals("a", decl.name());
        CallExpr call = (CallExpr) decl.init();
        assertEquals("ByteString", call.asmReturnType(),
            "ExpandFixedArrays dropped CallExpr.asmReturnType");
    }

    @Test
    void byteConcatIsAnnotatedAsBytes() throws Exception {
        String anf = PipelineTestSupport.anfJson(asmSrc(ASM_ARRAY_PROP), "Boardy.runar.ts");
        assertTrue(binOpPlusIsBytes(anf),
            "byte concat lost its \"bytes\" annotation (lowers to OP_ADD, not OP_CAT): " + anf);
    }

    @Test
    void asmControlWithoutFixedArrayIsUnchanged() throws Exception {
        String anf = PipelineTestSupport.anfJson(asmSrc(""), "Boardy.runar.ts");
        assertTrue(binOpPlusIsBytes(anf), anf);
    }

    // ------------------------------------------------------------------

    private static MethodNode methodNamed(ContractNode c, String name) {
        return c.methods().stream()
            .filter(m -> m.name().equals(name))
            .findFirst()
            .orElseThrow(() -> new AssertionError("no method " + name));
    }

    /**
     * True when the canonical ANF JSON carries a {@code bin_op} with op
     * {@code +} whose {@code result_type} is {@code bytes} — the annotation
     * StackLower reads to pick OP_CAT over OP_ADD.
     */
    private static boolean binOpPlusIsBytes(String anfJson) {
        int i = anfJson.indexOf("\"op\":\"+\"");
        while (i >= 0) {
            int end = anfJson.indexOf('}', i);
            int start = anfJson.lastIndexOf('{', i);
            if (start >= 0 && end > start
                && anfJson.substring(start, end).contains("\"result_type\":\"bytes\"")) {
                return true;
            }
            i = anfJson.indexOf("\"op\":\"+\"", i + 1);
        }
        return false;
    }
}

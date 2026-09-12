package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.Cli;
import runar.compiler.frontend.ParserDispatch;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.ir.stack.StackProgram;

/**
 * Port of the TypeScript reference test
 * {@code packages/runar-compiler/src/__tests__/n105-scriptbytes.test.ts}.
 *
 * <p>N-105 (1/2) — a NUMBER in the scriptBytes position of addRawOutput /
 * addDataOutput.
 *
 * <p>Same shape as N-098, one argument slot over, and the slot is the created
 * output's LOCKING SCRIPT.
 *
 * <p>This tier ACCEPTED {@code this.addRawOutput(1000n, n)} with
 * {@code n: bigint}, and the emitted script was byte-identical to the same
 * contract written with {@code n: ByteString} — measured, same digest, in all
 * six accepting tiers. The operand is not converted: whatever sits in that slot
 * is spliced into the output serialization as the output's script.
 *
 * <p>{@code lowerAddRawOutput} takes {@code OP_SIZE} of the operand,
 * varint-prefixes it and concatenates it after the 8-byte amount. A script
 * NUMBER on the stack is its minimal little-endian encoding, so the covenant
 * commits to an output whose locking script IS those bytes. Executed on the
 * real {@code @bsv/sdk} Spend engine against the exact 55-opcode window all six
 * tiers emit:
 *
 * <pre>
 *   n=0     -&gt; scriptLen 0   locking script (empty)     — anyone-can-spend
 *   n=81    -&gt; scriptLen 1   0x51 = OP_1                — anyone-can-spend
 *   n=118   -&gt; scriptLen 1   0x76 = OP_DUP              — anyone-can-spend
 *   n=1000  -&gt; scriptLen 2   0xe8 0x03, 0xe8 invalid    — unspendable
 * </pre>
 *
 * <p>N-098's failure mode was a wrong amount or a frozen UTXO. This one can
 * hand the whole output to anybody who sees it, which is why it is a gate.
 *
 * <p>The rejection is asserted through the SAME chain
 * {@code runar.lang.sdk.CompileCheck} runs, so a Java contract author asking
 * "is this valid Rúnar?" gets the same answer the CLI gives.
 *
 * <p>{@code <unknown>} stays ACCEPTED exactly as TS has it — a private helper's
 * declared return type is discarded at parse time in every tier.
 */
class N105ScriptBytesTest {

    private static final String HEAD =
        "import { StatefulSmartContract, ByteString, Ripemd160, assert } from 'runar-lang';\n"
        + "class C extends StatefulSmartContract {\n"
        + "  count: bigint;\n"
        + "  readonly base: bigint;\n"
        + "  readonly flag: boolean;\n"
        + "  readonly blob: ByteString;\n"
        + "  readonly pkh: Ripemd160;\n"
        + "  constructor(count: bigint, base: bigint, flag: boolean, blob: ByteString, pkh: Ripemd160) {\n"
        + "    super(count, base, flag, blob, pkh);\n"
        + "    this.count = count;\n"
        + "    this.base = base;\n"
        + "    this.flag = flag;\n"
        + "    this.blob = blob;\n"
        + "    this.pkh = pkh;\n"
        + "  }\n"
        + "  private bytes(): ByteString { return this.blob; }\n";

    private static String contract(String body) {
        return HEAD + body + "}\n";
    }

    // --- REJECT ------------------------------------------------------------

    private static final String RAW_BIGINT_SCRIPT = contract(
        "  public m(n: bigint) {\n"
        + "    assert(n > 0n);\n"
        + "    this.count = this.count + n;\n"
        + "    this.addOutput(1000n, this.count);\n"
        + "    this.addRawOutput(500n, this.base);\n"
        + "  }\n");

    private static final String DATA_BIGINT_SCRIPT = contract(
        "  public m(n: bigint) {\n"
        + "    assert(n > 0n);\n"
        + "    this.count = this.count + n;\n"
        + "    this.addOutput(1000n, this.count);\n"
        + "    this.addDataOutput(500n, this.base);\n"
        + "  }\n");

    private static final String RAW_BOOLEAN_SCRIPT = contract(
        "  public m(n: bigint) {\n"
        + "    assert(n > 0n);\n"
        + "    this.count = this.count + n;\n"
        + "    this.addOutput(1000n, this.count);\n"
        + "    this.addRawOutput(500n, this.flag);\n"
        + "  }\n");

    // --- ACCEPT (over-rejection guards) ------------------------------------

    private static final String RAW_BYTESTRING_SCRIPT = contract(
        "  public m(n: bigint) {\n"
        + "    assert(n > 0n);\n"
        + "    this.count = this.count + n;\n"
        + "    this.addOutput(1000n, this.count);\n"
        + "    this.addRawOutput(500n, this.blob);\n"
        + "  }\n");

    private static final String RAW_STATE_SCRIPT = contract(
        "  public m(n: bigint) {\n"
        + "    assert(n > 0n);\n"
        + "    this.count = this.count + n;\n"
        + "    this.addOutput(1000n, this.count);\n"
        + "    this.addRawOutput(500n, this.getStateScript());\n"
        + "  }\n");

    /**
     * A ByteString SUBTYPE. TS's rule is {@code isSubtype(scriptType,
     * "ByteString")}, not equality, so Ripemd160 must keep compiling.
     */
    private static final String RAW_SUBTYPE_SCRIPT = contract(
        "  public m(n: bigint) {\n"
        + "    assert(n > 0n);\n"
        + "    this.count = this.count + n;\n"
        + "    this.addOutput(1000n, this.count);\n"
        + "    this.addRawOutput(500n, this.pkh);\n"
        + "  }\n");

    /**
     * A private helper's declared return type is discarded at parse time in
     * every tier, so this infers as {@code <unknown>}. TS escapes it; every
     * port must too.
     */
    private static final String RAW_HELPER_SCRIPT = contract(
        "  public m(n: bigint) {\n"
        + "    assert(n > 0n);\n"
        + "    this.count = this.count + n;\n"
        + "    this.addOutput(1000n, this.count);\n"
        + "    this.addRawOutput(500n, this.bytes());\n"
        + "  }\n");

    private static final String DATA_BYTESTRING_SCRIPT = contract(
        "  public m(n: bigint) {\n"
        + "    assert(n > 0n);\n"
        + "    this.count = this.count + n;\n"
        + "    this.addOutput(1000n, this.count);\n"
        + "    this.addDataOutput(500n, this.blob);\n"
        + "  }\n");

    // -----------------------------------------------------------------------

    /** The exact chain {@code runar.lang.sdk.CompileCheck} runs. */
    private static List<String> frontendErrors(String src) throws Exception {
        ContractNode c = ParserDispatch.parse(src, "C.runar.ts");
        Validate.run(c);
        c = ExpandFixedArrays.run(c);
        return Typecheck.collect(c);
    }

    private static void assertRejected(String src, String needle) throws Exception {
        List<String> errs = frontendErrors(src);
        assertFalse(
            errs.isEmpty(),
            "expected the Java frontend to REJECT this source; it accepted it. "
                + "The TypeScript reference refuses it, and the accepting tiers spliced "
                + "the number into the created output's locking script with no conversion."
        );
        assertTrue(
            errs.stream().anyMatch(e -> e.contains(needle)),
            "expected a diagnostic containing \"" + needle + "\", got " + errs
        );
    }

    private static String hex(String src) throws Exception {
        ContractNode contract = ParserDispatch.parse(src, "C.runar.ts");
        Validate.run(contract);
        contract = ExpandFixedArrays.run(contract);
        Typecheck.run(contract);
        AnfProgram anf = AnfLower.run(contract);
        anf = Cli.optimizeAnf(anf, false); // fold-ON, the user-facing default
        StackProgram stack = StackLower.run(anf);
        return Emit.run(Peephole.run(stack));
    }

    // --- the defect --------------------------------------------------------

    @Test
    void addRawOutputRejectsBigintScriptBytes() throws Exception {
        assertRejected(
            RAW_BIGINT_SCRIPT,
            "addRawOutput() second argument (scriptBytes) must be ByteString, got 'bigint'");
    }

    @Test
    void addDataOutputRejectsBigintScriptBytes() throws Exception {
        assertRejected(
            DATA_BIGINT_SCRIPT,
            "addDataOutput() second argument (scriptBytes) must be ByteString, got 'bigint'");
    }

    @Test
    void addRawOutputRejectsBooleanScriptBytes() throws Exception {
        assertRejected(
            RAW_BOOLEAN_SCRIPT,
            "addRawOutput() second argument (scriptBytes) must be ByteString, got 'boolean'");
    }

    // --- controls ----------------------------------------------------------

    @Test
    void acceptedScriptBytesPositions() throws Exception {
        for (String src : List.of(
                RAW_BYTESTRING_SCRIPT,
                RAW_STATE_SCRIPT,
                RAW_SUBTYPE_SCRIPT,
                RAW_HELPER_SCRIPT,
                DATA_BYTESTRING_SCRIPT)) {
            assertTrue(frontendErrors(src).isEmpty(), "a legal scriptBytes position was rejected");
            assertFalse(hex(src).isEmpty(), "compiled to an empty script");
        }
    }

    /**
     * Non-vacuity: "it compiled" would also hold for a tier that discarded the
     * scriptBytes operand. Two DIFFERENT ByteString operands must lower to
     * different scripts.
     */
    @Test
    void scriptBytesOperandReachesCodegen() throws Exception {
        assertNotEquals(hex(RAW_BYTESTRING_SCRIPT), hex(RAW_STATE_SCRIPT),
            "two different scriptBytes operands produced the same script — the operand is being dropped");
    }
}

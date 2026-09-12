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
 * {@code packages/runar-compiler/src/__tests__/n098-bytestring-satoshis.test.ts}.
 *
 * <p>N-098 — a ByteString in the SATOSHIS position of an output intrinsic.
 *
 * <p>This tier ACCEPTED all three shapes. It was not a missing diagnostic: the
 * ByteString was lowered into the satoshis slot with NO conversion, and the
 * emitted script was byte-identical to the same contract written with
 * {@code blob: bigint} — 1358 hexchars, same digest, in all six accepting tiers.
 *
 * <p>{@code lowerAddOutput} prepends the satoshis operand as
 * {@code OP_8 OP_NUM2BIN}, so the covenant commits to whatever those bytes
 * decode to as a script number. Executed on the real {@code @bsv/sdk} Spend
 * engine with {@code blob = 0x2a}, a 42-satoshi continuation VALIDATES and the
 * 1000-satoshi one the author funded is REJECTED. Bigger blobs fail shut rather
 * than safe: {@code 0xcafebabefeed0001} demands 7.2e16 satoshis and a 20-byte
 * hash aborts the script at {@code OP_NUM2BIN}, leaving the UTXO permanently
 * unspendable.
 *
 * <p>The rule ported here is the TypeScript reference's, wording included. Only
 * the FIRST argument is checked. TS additionally checks arity, the state-value
 * types and the {@code scriptBytes} argument; none of those are ported here and
 * none of them are this finding.
 *
 * <p>The rejection is asserted through the SAME chain
 * {@code runar.lang.sdk.CompileCheck} runs ({@code ParserDispatch.parse ->
 * Validate.run -> ExpandFixedArrays.run -> Typecheck}), so a Java contract
 * author asking "is this valid Rúnar?" gets the same answer the CLI gives —
 * the distinction R-092 had to fix once already.
 *
 * <p>The ACCEPT block carries the real risk in a change like this.
 * {@code <unknown>} must stay accepted: a private helper's declared return type
 * is discarded at parse time in every tier, so {@code this.sats()} infers as
 * {@code <unknown>}, and TS has always escaped it here.
 */
class N098ByteStringSatoshisTest {

    private static final String HEAD =
        "import { StatefulSmartContract, ByteString, assert } from 'runar-lang';\n"
        + "class C extends StatefulSmartContract {\n"
        + "  count: bigint;\n"
        + "  readonly base: bigint;\n"
        + "  readonly blob: ByteString;\n"
        + "  constructor(count: bigint, base: bigint, blob: ByteString) {\n"
        + "    super(count, base, blob);\n"
        + "    this.count = count;\n"
        + "    this.base = base;\n"
        + "    this.blob = blob;\n"
        + "  }\n"
        + "  private sats(): bigint { return this.base; }\n";

    private static String contract(String body) {
        return HEAD + body + "}\n";
    }

    // --- REJECT ------------------------------------------------------------

    private static final String ADD_OUTPUT = contract(
        "  public m(n: bigint) {\n"
        + "    assert(n > 0n);\n"
        + "    this.count = this.count + n;\n"
        + "    this.addOutput(this.blob, this.count);\n"
        + "  }\n");

    private static final String ADD_RAW_OUTPUT = contract(
        "  public m(n: bigint) {\n"
        + "    assert(n > 0n);\n"
        + "    this.count = this.count + n;\n"
        + "    this.addOutput(1000n, this.count);\n"
        + "    this.addRawOutput(this.blob, this.blob);\n"
        + "  }\n");

    private static final String ADD_DATA_OUTPUT = contract(
        "  public m(n: bigint) {\n"
        + "    assert(n > 0n);\n"
        + "    this.count = this.count + n;\n"
        + "    this.addOutput(1000n, this.count);\n"
        + "    this.addDataOutput(this.blob, this.blob);\n"
        + "  }\n");

    // --- ACCEPT (over-rejection guards) ------------------------------------

    private static final String LITERAL_SATS = contract(
        "  public m(n: bigint) {\n"
        + "    assert(n > 0n);\n"
        + "    this.count = this.count + n;\n"
        + "    this.addOutput(1000n, this.count);\n"
        + "  }\n");

    private static final String PARAM_SATS = contract(
        "  public m(n: bigint) {\n"
        + "    assert(n > 0n);\n"
        + "    this.count = this.count + n;\n"
        + "    this.addOutput(n, this.count);\n"
        + "  }\n");

    private static final String PROPERTY_SATS = contract(
        "  public m(n: bigint) {\n"
        + "    assert(n > 0n);\n"
        + "    this.count = this.count + n;\n"
        + "    this.addOutput(this.base, this.count);\n"
        + "  }\n");

    /** A private helper's declared return type is discarded at parse time in
     *  EVERY tier, so this infers as {@code <unknown>}. Must stay ACCEPTED. */
    private static final String HELPER_SATS = contract(
        "  public m(n: bigint) {\n"
        + "    assert(n > 0n);\n"
        + "    this.count = this.count + n;\n"
        + "    this.addOutput(this.sats(), this.count);\n"
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
                + "The TypeScript reference refuses it, and the accepting tiers lowered "
                + "the ByteString into the satoshis slot with no conversion."
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
    void addOutputRejectsByteStringSatoshis() throws Exception {
        assertRejected(
            ADD_OUTPUT,
            "addOutput() first argument (satoshis) must be bigint, got 'ByteString'");
    }

    @Test
    void addRawOutputRejectsByteStringSatoshis() throws Exception {
        assertRejected(
            ADD_RAW_OUTPUT,
            "addRawOutput() first argument (satoshis) must be bigint, got 'ByteString'");
    }

    @Test
    void addDataOutputRejectsByteStringSatoshis() throws Exception {
        assertRejected(
            ADD_DATA_OUTPUT,
            "addDataOutput() first argument (satoshis) must be bigint, got 'ByteString'");
    }

    // --- controls ----------------------------------------------------------

    @Test
    void acceptedSatoshisPositions() throws Exception {
        for (String src : List.of(LITERAL_SATS, PARAM_SATS, PROPERTY_SATS, HELPER_SATS)) {
            assertTrue(frontendErrors(src).isEmpty(), "a legal satoshis position was rejected");
            assertFalse(hex(src).isEmpty(), "compiled to an empty script");
        }
    }

    /**
     * Non-vacuity: "it compiled" would also hold for a tier that discarded the
     * satoshis operand entirely. A literal and a runtime parameter must lower
     * to DIFFERENT scripts. Every tier's own N-098 test makes this same
     * assertion.
     */
    @Test
    void satoshisOperandReachesCodegen() throws Exception {
        String lit = hex(LITERAL_SATS);
        String param = hex(PARAM_SATS);
        assertNotEquals(lit, param,
            "literal and parameter satoshis produced the same script — the operand is being dropped");
        assertTrue(lit.contains("02e803"), // PUSH(2) 0xe8 0x03 == 1000
            "literal 1000n does not appear in the emitted script");
    }
}

package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import runar.compiler.Cli;
import runar.compiler.ir.anf.AnfMethod;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.ast.ContractNode;

/**
 * A terminal read of a FIXED-SIZE state field goes stale when a SIBLING field is
 * variable-length. R-074, the third member of the issue-#100 family.
 *
 * <p>{@code lowerDeserializeState} picks its extraction strategy from a
 * CONTRACT-level fact — {@code hasVariableLength}, i.e. "does ANY mutable
 * property carry a push-data length prefix". When that is true the state section
 * can only be located through the {@code _codePart}-relative offset, so the
 * WHOLE deserialization is gated on {@code sm.has("_codePart")}; without it the
 * pass takes its {@code OP_SPLIT}/{@code OP_2DROP} shortcut, pushes NO mutable
 * property at all, and every later {@code load_prop} silently resolves to the
 * DEPLOY-TIME constructor placeholder baked into the locking script.
 *
 * <p>{@link StackLower#methodRequiresCodePart}, which decides whether
 * {@code _codePart} is on the stack, asked a strictly NARROWER, METHOD-level
 * question: "does THIS method read a var-length property". A terminal method
 * that reads only the {@code bigint} sibling answered no, so {@code _codePart}
 * was never provisioned and the contract's own live state became invisible.
 *
 * <p>The two questions must agree. {@code 6dc1979b} (R-015 / CL-BUG-138) fixed a
 * different divergence in this same predicate — which TYPES count as
 * variable-length — and left this one live: there the method read the
 * var-length field itself, here it merely shares a contract with one.
 *
 * <p>Executed harm, proven on the real {@code @bsv/sdk} VM: deploy
 * {@code count=1}, call {@code bump(7)}, then terminal {@code check}. Pre-fix
 * {@code check(7)} is REJECTED and {@code check(1)} VALIDATES — the stale
 * deploy-time value authorises a real spend.
 *
 * <p>The matched control is the same contract with {@code tag: bigint}: no
 * var-length property, {@code hasVariableLength} false, the fixed-width split
 * path, and a correct live-state read all along. It must stay BYTE-IDENTICAL —
 * the fix is confined to contracts that actually declare var-length state.
 */
class StaleStateUnrelatedVarLenTest {

    private static final String FILE = "StaleStateProbe.runar.ts";

    /**
     * {@code count} is fixed-size and IS read by the terminal method;
     * {@code tag} is variable-length and is NOT touched by it.
     */
    private static final String PROBE_SRC =
        "import { StatefulSmartContract, assert, ByteString } from 'runar-lang';\n"
        + "class StaleStateProbe extends StatefulSmartContract {\n"
        + "  count: bigint;\n"
        + "  tag: ByteString;\n"
        + "  constructor(count: bigint, tag: ByteString) {\n"
        + "    super(count, tag);\n"
        + "    this.count = count;\n"
        + "    this.tag = tag;\n"
        + "  }\n"
        + "  public check(expected: bigint): void { assert(this.count === expected); }\n"
        + "}\n";

    /**
     * Matched control: identical in every respect except {@code tag}'s type,
     * which is the single input to {@code hasVariableLength}.
     */
    private static final String CONTROL_SRC =
        "import { StatefulSmartContract, assert } from 'runar-lang';\n"
        + "class StaleStateProbe extends StatefulSmartContract {\n"
        + "  count: bigint;\n"
        + "  tag: bigint;\n"
        + "  constructor(count: bigint, tag: bigint) {\n"
        + "    super(count, tag);\n"
        + "    this.count = count;\n"
        + "    this.tag = tag;\n"
        + "  }\n"
        + "  public check(expected: bigint): void { assert(this.count === expected); }\n"
        + "}\n";

    /**
     * Same shape, reached through a private helper. Private methods are INLINED
     * into the caller's stack context (deep-review finding C18), so the
     * recursion {@code methodReadsVarLenState} already performs must keep
     * working once the property set it is handed is widened.
     */
    private static final String PRIVATE_HELPER_SRC =
        "import { StatefulSmartContract, assert, ByteString } from 'runar-lang';\n"
        + "class StaleStateProbe extends StatefulSmartContract {\n"
        + "  count: bigint;\n"
        + "  tag: ByteString;\n"
        + "  constructor(count: bigint, tag: ByteString) {\n"
        + "    super(count, tag);\n"
        + "    this.count = count;\n"
        + "    this.tag = tag;\n"
        + "  }\n"
        + "  private current(): bigint { return this.count; }\n"
        + "  public check(expected: bigint): void { assert(this.current() === expected); }\n"
        + "}\n";

    /**
     * A terminal method that reads NO mutable state at all.
     * {@code hasVariableLength} is true, but there is nothing to deserialize, so
     * {@code _codePart} must stay off the stack — the fix must not provision it
     * unconditionally.
     */
    private static final String NO_STATE_READ_SRC =
        "import { StatefulSmartContract, assert, ByteString } from 'runar-lang';\n"
        + "class StaleStateProbe extends StatefulSmartContract {\n"
        + "  count: bigint;\n"
        + "  tag: ByteString;\n"
        + "  constructor(count: bigint, tag: ByteString) {\n"
        + "    super(count, tag);\n"
        + "    this.count = count;\n"
        + "    this.tag = tag;\n"
        + "  }\n"
        + "  public check(expected: bigint): void { assert(expected > 0); }\n"
        + "}\n";

    /**
     * Cross-tier pins, captured from the five tiers that already carry the fix
     * (TypeScript, Go, Rust, Python, Ruby). sha256 is taken over the ASCII hex
     * string, exactly as the sibling Python and Zig tests do.
     */
    private static final int PROBE_FIXED_LEN = 1268;
    private static final String PROBE_FIXED_SHA256 =
        "a7966788abe3a2b5eeedccc5a1430b14fa51d55ef7a44c705ed98cbd5a887ae0";

    /**
     * The broken script this finding is about. Pinned as a MUST-NOT-EQUAL so a
     * future regression cannot quietly restore it.
     */
    private static final String PROBE_BROKEN_SHA256 =
        "150cb2a01cca2eb26bbbe02e2c090aa5d0c33957b07a7e385d951ec6452e0fb8";

    /** Outside the fix's blast radius — must not move. */
    private static final int CONTROL_FIXED_LEN = 940;
    private static final String CONTROL_SHA256 =
        "4832543947423af01033fb80269f838e04a3b9da95634ec038e704239e37e935";

    /**
     * The BIP-143 scriptCode varint-strip cascade ({@code <fd00> OP_LESSTHAN
     * OP_IF}) emitted ONLY on the {@code _codePart}-relative live-state path —
     * never on the fixed-width path and never on the discard shortcut. Its
     * presence is a structural proof that the method reads the state section
     * rather than the constructor placeholder.
     */
    private static final String LIVE_STATE_MARKER_HEX = "02fd009f63";

    private static String sha256(String hex) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256")
            .digest(hex.getBytes(StandardCharsets.US_ASCII));
        StringBuilder sb = new StringBuilder(64);
        for (byte b : digest) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    private static boolean requiresCodePart(String src) throws Exception {
        ContractNode contract = PipelineTestSupport.parseValidated(src, FILE);
        contract = ExpandFixedArrays.run(contract);
        Typecheck.run(contract);
        AnfProgram program = Cli.optimizeAnf(AnfLower.run(contract), /* disableConstantFolding */ true);
        Map<String, AnfMethod> privateMethods = new HashMap<>(StackLower.privateMethodMap(program));
        AnfMethod target = program.methods().stream()
            .filter(m -> m.name().equals("check"))
            .findFirst()
            .orElseThrow(() -> new AssertionError("method 'check' not found"));
        return StackLower.methodRequiresCodePart(target, program.properties(), privateMethods);
    }

    @Test
    void terminalReadBesideAVarLenSiblingReadsLiveState() throws Exception {
        String hex = PipelineTestSupport.hex(PROBE_SRC, FILE);
        assertTrue(hex.contains(LIVE_STATE_MARKER_HEX),
            "terminal read of `count` did not take the `_codePart`-relative live-state path");
        assertEquals(PROBE_FIXED_LEN, hex.length(),
            "probe script length diverges from the five tiers that already carry the fix");
        assertNotEquals(PROBE_BROKEN_SHA256, sha256(hex),
            "probe still compiles to the stale deploy-time-placeholder script");
        assertEquals(PROBE_FIXED_SHA256, sha256(hex),
            "probe script is not byte-identical to the cross-tier fixed script");
    }

    @Test
    void probeAdvertisesUsesCodePart() throws Exception {
        // The ABI shape, not just the byte count: the SDK reads this flag to
        // decide whether to push `_codePart` into the unlocking script.
        assertTrue(requiresCodePart(PROBE_SRC));
    }

    @Test
    void privateHelperVariantMatchesTheDirectRead() throws Exception {
        assertEquals(PipelineTestSupport.hex(PROBE_SRC, FILE),
            PipelineTestSupport.hex(PRIVATE_HELPER_SRC, FILE));
    }

    @Test
    void controlWithoutAVarLengthSiblingIsByteUnchanged() throws Exception {
        String hex = PipelineTestSupport.hex(CONTROL_SRC, FILE);
        assertEquals(CONTROL_FIXED_LEN, hex.length());
        assertEquals(CONTROL_SHA256, sha256(hex));
        assertFalse(requiresCodePart(CONTROL_SRC));
    }

    @Test
    void terminalMethodReadingNoStateDoesNotProvisionCodePart() throws Exception {
        assertFalse(requiresCodePart(NO_STATE_READ_SRC));
    }
}

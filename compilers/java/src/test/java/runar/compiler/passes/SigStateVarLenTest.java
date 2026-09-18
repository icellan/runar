package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import runar.compiler.Cli;
import runar.compiler.ir.anf.AnfMethod;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.ast.ContractNode;

/**
 * {@code Sig} and {@code SigHashPreimage} state fields are push-data-framed
 * variable-length state, exactly like {@code ByteString}, on BOTH the write and
 * the read side.
 *
 * <p>{@code StackLower} kept three lists of "which state types carry a
 * push-data length prefix":
 *
 * <ul>
 *   <li>{@code isVariableLengthStateType} + the deserialize size table
 *       ({@code :3753}) + the var-length parse loop ({@code :3901}) — all say
 *       {@code ByteString | Sig | SigHashPreimage};
 *   <li>the two state SERIALIZERS ({@code :3371} and {@code :4122}) — said
 *       {@code "ByteString".equals(prop.type())};
 *   <li>the {@code varLenProps} set inside {@link
 *       StackLower#methodRequiresCodePart} ({@code :786}) — same.
 * </ul>
 *
 * <p>Two faces, both fund loss. WRITE: a mutating method wrote the continuation
 * state RAW, with no length prefix, while the reader in the NEXT spend
 * push-data-decodes it and takes the DER {@code 0x30} as a length-48 push —
 * deploy succeeds, the first spend succeeds, and the UTXO that spend creates is
 * unspendable. READ: for a TERMINAL method reading a mutable {@code Sig} field
 * {@code usesCodePart} stayed false, the deserializer took its "no
 * {@code _codePart}" shortcut and pushed no mutable property at all, so every
 * {@code load_prop} fell through to the DEPLOY-TIME constructor placeholder.
 *
 * <p>The deploy-time writer settles which list is right: every SDK's
 * {@code encodeStateValue} enumerates the fixed-size types (PubKey, Addr,
 * Ripemd160, Sha256, Point, P256Point, P384Point) and push-data-frames the rest.
 *
 * <p>The lock: a {@code Sig} / {@code SigHashPreimage} field must compile
 * BYTE-IDENTICALLY to the same contract with a {@code ByteString} field — the
 * path that was already correct. {@code RabinSig} (a bigint alias stored as a
 * bare 8-byte NUM2BIN word) and {@code PubKey} (33 raw bytes) are the negative
 * controls and must stay DIFFERENT.
 */
class SigStateVarLenTest {

    private static final String WRITE_FILE = "VarLenStateWrite.runar.ts";
    private static final String READ_FILE = "VarLenStateRead.runar.ts";

    /** Mutating method — drives the state-continuation WRITE path. */
    private static String writeSrc(String propType) {
        return "import { StatefulSmartContract } from 'runar-lang';\n"
            + "class VarLenStateWrite extends StatefulSmartContract {\n"
            + "  tag: " + propType + ";\n"
            + "  constructor(tag: " + propType + ") { super(tag); this.tag = tag; }\n"
            + "  public update(next: " + propType + "): void { this.tag = next; }\n"
            + "}\n";
    }

    /** Terminal read of the field — drives {@link StackLower#methodRequiresCodePart}. */
    private static String readSrc(String propType) {
        return "import { StatefulSmartContract, assert, len } from 'runar-lang';\n"
            + "class VarLenStateRead extends StatefulSmartContract {\n"
            + "  tag: " + propType + ";\n"
            + "  constructor(tag: " + propType + ") { super(tag); this.tag = tag; }\n"
            + "  public check(expected: bigint): void { assert(len(this.tag) === expected); }\n"
            + "}\n";
    }

    /** Fold-OFF ANF, so {@link StackLower#methodRequiresCodePart} sees the real inputs. */
    private static AnfProgram anf(String src, String file) throws Exception {
        ContractNode contract = PipelineTestSupport.parseValidated(src, file);
        contract = ExpandFixedArrays.run(contract);
        Typecheck.run(contract);
        return Cli.optimizeAnf(AnfLower.run(contract), /* disableConstantFolding */ true);
    }

    private static boolean requiresCodePart(String src, String file, String method) throws Exception {
        AnfProgram program = anf(src, file);
        Map<String, AnfMethod> privateMethods = new HashMap<>(StackLower.privateMethodMap(program));
        AnfMethod target = program.methods().stream()
            .filter(m -> m.name().equals(method))
            .findFirst()
            .orElseThrow(() -> new AssertionError("method '" + method + "' not found"));
        return StackLower.methodRequiresCodePart(target, program.properties(), privateMethods);
    }

    // -----------------------------------------------------------------------
    // WRITE path — the continuation must be framed the way the reader parses it.
    // -----------------------------------------------------------------------

    @ParameterizedTest
    @ValueSource(strings = {"Sig", "SigHashPreimage"})
    void mutatingMethodFramesLikeByteString(String propType) throws Exception {
        String control = PipelineTestSupport.hex(writeSrc("ByteString"), WRITE_FILE);
        String got = PipelineTestSupport.hex(writeSrc(propType), WRITE_FILE);
        assertEquals(control.length(), got.length(),
            "a mutable " + propType + " field does not push-data-frame its continuation state");
        assertEquals(control, got,
            "a mutable " + propType + " field does not frame its continuation like ByteString");
    }

    // -----------------------------------------------------------------------
    // READ path — a terminal read needs the implicit _codePart parameter.
    // -----------------------------------------------------------------------

    @ParameterizedTest
    @ValueSource(strings = {"Sig", "SigHashPreimage"})
    void terminalReadMatchesByteString(String propType) throws Exception {
        String control = PipelineTestSupport.hex(readSrc("ByteString"), READ_FILE);
        String got = PipelineTestSupport.hex(readSrc(propType), READ_FILE);
        assertEquals(control.length(), got.length(),
            "a terminal read of a mutable " + propType + " field diverges from the ByteString control");
        assertEquals(control, got,
            "a terminal read of a mutable " + propType + " field diverges from the ByteString control");
    }

    @ParameterizedTest
    @ValueSource(strings = {"Sig", "SigHashPreimage", "ByteString"})
    void terminalReadRequiresCodePart(String propType) throws Exception {
        // The ABI shape, not just the byte count: this is the flag the artifact
        // assembler publishes as abi.methods[].usesCodePart, which the SDK reads
        // to decide whether to push _codePart into the unlocking script.
        assertTrue(requiresCodePart(readSrc(propType), READ_FILE, "check"),
            "a terminal read of a mutable " + propType + " field must take the implicit _codePart parameter");
    }

    // -----------------------------------------------------------------------
    // Negative controls — the types this change must NOT touch.
    // -----------------------------------------------------------------------

    @Test
    void fixedWidthStateIsNotPushDataFramed() throws Exception {
        String control = PipelineTestSupport.hex(writeSrc("ByteString"), WRITE_FILE);
        for (String propType : List.of("RabinSig", "RabinPubKey", "PubKey")) {
            assertNotEquals(control, PipelineTestSupport.hex(writeSrc(propType), WRITE_FILE),
                propType + " compiled identically to ByteString — it must keep its fixed-width framing, "
                + "or the assertions above stop discriminating");
        }
    }
}

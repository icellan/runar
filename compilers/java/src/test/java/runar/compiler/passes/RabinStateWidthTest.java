package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * {@code RabinSig} and {@code RabinPubKey} are {@code bigint} ALIASES. A mutable
 * one is stored in the state section as a bare 8-byte OP_NUM2BIN word, on BOTH
 * sides.
 *
 * <p>This tier's READER already says so in three places — {@code
 * NUMERIC_STATE_TYPES} in {@link StackLower}, the deserialize size table (8) and
 * the fixed state-section length (8). Its two state SERIALIZERS did not: they
 * tested {@code "bigint".equals(prop.type())} literally, so a mutable Rabin
 * field went into the accumulator in its MINIMAL script-number encoding with no
 * NUM2BIN at all.
 *
 * <p>Same class of writer/reader split as {@link SigStateVarLenTest}, and the
 * same fund loss: for any value whose minimal encoding is not exactly 8 bytes
 * the continuation this contract builds cannot be re-read by its own script.
 * Deploy succeeds, the first spend succeeds, and the UTXO it creates is dead.
 *
 * <p>Cause: {@code 31276a06} widened writer AND reader in the TypeScript
 * reference; {@code e06f8c2c} widened only Go's reader, and this tier followed
 * Go.
 *
 * <p>The lock: a mutable Rabin field must compile BYTE-IDENTICALLY to the same
 * contract with a {@code bigint} field — the path whose writer and reader are
 * known to agree. {@code ByteString} / {@code Sig} (framed) and {@code PubKey}
 * (33 raw) stay the negative controls, so the equality cannot be satisfied by
 * collapsing every state type onto one shape.
 */
class RabinStateWidthTest {

    private static final String WRITE_FILE = "RabinStateWrite.runar.ts";
    private static final String ADD_OUTPUT_FILE = "RabinStateAddOutput.runar.ts";

    /** Mutating method, implicit continuation — the compute-state-bytes writer. */
    private static String writeSrc(String propType) {
        return "import { StatefulSmartContract } from 'runar-lang';\n"
            + "class RabinStateWrite extends StatefulSmartContract {\n"
            + "  tag: " + propType + ";\n"
            + "  constructor(tag: " + propType + ") { super(tag); this.tag = tag; }\n"
            + "  public update(next: " + propType + "): void { this.tag = next; }\n"
            + "}\n";
    }

    /** Mutating method with an EXPLICIT addOutput — the lowerAddOutput writer. */
    private static String addOutputSrc(String propType) {
        return "import { StatefulSmartContract } from 'runar-lang';\n"
            + "class RabinStateAddOutput extends StatefulSmartContract {\n"
            + "  tag: " + propType + ";\n"
            + "  constructor(tag: " + propType + ") { super(tag); this.tag = tag; }\n"
            + "  public update(next: " + propType + "): void { this.tag = next; this.addOutput(1000n, next); }\n"
            + "}\n";
    }

    private static String hex(String shape, String propType) throws Exception {
        return "addOutput".equals(shape)
            ? PipelineTestSupport.hex(addOutputSrc(propType), ADD_OUTPUT_FILE)
            : PipelineTestSupport.hex(writeSrc(propType), WRITE_FILE);
    }

    // -----------------------------------------------------------------------
    // The decisive equality: the writer must emit the reader's 8-byte word.
    // -----------------------------------------------------------------------

    @ParameterizedTest
    @CsvSource({
        "continuation, RabinSig",
        "continuation, RabinPubKey",
        "addOutput,    RabinSig",
        "addOutput,    RabinPubKey",
    })
    void mutableRabinFieldWritesTheSameFixedWordAsBigint(String shape, String propType) throws Exception {
        String control = hex(shape, "bigint");
        String got = hex(shape, propType);
        assertEquals(control.length(), got.length(),
            shape + ": a mutable " + propType + " field is not serialized as a fixed 8-byte word");
        assertEquals(control, got,
            shape + ": a mutable " + propType + " field does not serialize like bigint — "
                + "the writer disagrees with its own 8-byte reader");
    }

    // -----------------------------------------------------------------------
    // Negative controls — the equality must stay discriminating.
    // -----------------------------------------------------------------------

    @ParameterizedTest
    @CsvSource({
        "continuation, ByteString",
        "continuation, Sig",
        "continuation, PubKey",
        "addOutput,    ByteString",
        "addOutput,    Sig",
        "addOutput,    PubKey",
    })
    void otherStateTypesStayDistinctFromBigint(String shape, String propType) throws Exception {
        assertNotEquals(hex(shape, "bigint"), hex(shape, propType),
            shape + ": a mutable " + propType + " field compiled identically to bigint — "
                + "the Rabin equality no longer discriminates");
    }
}

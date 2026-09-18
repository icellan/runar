package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import runar.compiler.frontend.ParserDispatch;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.ir.ast.PropertyNode;

/**
 * Issue #109 — {@code /** @embedAlways *&#47;} readonly-field DCE opt-out. Port
 * of embed-always.test.ts: parser flag, DCE preservation into a constructor
 * slot (byte parity with the TypeScript reference), and the strip warning.
 */
class EmbedAlwaysTest {

    private static String source(String directive) {
        return "class Meta extends SmartContract {\n"
            + "  readonly pubKeyHash: Addr;\n"
            + "  " + directive + "\n"
            + "  readonly metadataId: ByteString;\n"
            + "  constructor(pubKeyHash: Addr, metadataId: ByteString) {\n"
            + "    super(pubKeyHash, metadataId); this.pubKeyHash = pubKeyHash; this.metadataId = metadataId;\n"
            + "  }\n"
            + "  public unlock(sig: Sig, pubKey: PubKey) {\n"
            + "    assert(hash160(pubKey) === this.pubKeyHash); assert(checkSig(sig, pubKey));\n"
            + "  }\n"
            + "}\n";
    }

    private static PropertyNode prop(ContractNode c, String name) {
        return c.properties().stream().filter(p -> p.name().equals(name)).findFirst().orElseThrow();
    }

    // ---- Parser ---------------------------------------------------------------

    @Test
    void setsEmbedAlwaysOnJsdocDirective() throws Exception {
        ContractNode c = ParserDispatch.parse(source("/** @embedAlways */"), "Meta.runar.ts");
        assertTrue(prop(c, "metadataId").embedAlways());
        assertFalse(prop(c, "pubKeyHash").embedAlways());
    }

    @Test
    void recognizesLineCommentDirective() throws Exception {
        ContractNode c = ParserDispatch.parse(source("// @embedAlways"), "Meta.runar.ts");
        assertTrue(prop(c, "metadataId").embedAlways());
    }

    @Test
    void leavesEmbedAlwaysUnsetWithNoDirective() throws Exception {
        ContractNode c = ParserDispatch.parse(source(""), "Meta.runar.ts");
        assertFalse(prop(c, "metadataId").embedAlways());
    }

    // ---- Preservation (byte parity with the TypeScript reference) ------------

    // Fold-OFF locking-script templates captured from the TS compiler
    // (packages/runar-compiler) compile(src, { disableConstantFolding: true }).scriptHex.
    private static final String TS_PLAIN_HEX = "76a90088ac";
    private static final String TS_EMBED_HEX = "0078a900887b7bac77";

    @Test
    void unannotatedFieldIsEliminated() throws Exception {
        String plain = PipelineTestSupport.hex(source(""), "Meta.runar.ts");
        assertEquals(TS_PLAIN_HEX, plain, "un-annotated template must match the TS reference");
    }

    @Test
    void annotatedFieldIsPreservedByteIdenticalToTs() throws Exception {
        String embed = PipelineTestSupport.hex(source("/** @embedAlways */"), "Meta.runar.ts");
        assertEquals(TS_EMBED_HEX, embed, "@embedAlways template must match the TS reference");
    }

    @Test
    void annotatedHexCarriesMoreBytesThanUnannotated() throws Exception {
        String plain = PipelineTestSupport.hex(source(""), "Meta.runar.ts");
        String embed = PipelineTestSupport.hex(source("/** @embedAlways */"), "Meta.runar.ts");
        assertNotEquals(plain, embed);
        assertTrue(embed.length() > plain.length(), "embed template must carry the extra field bytes");
    }

    // ---- Warning (Option 4) ---------------------------------------------------

    @Test
    void warnsForEliminatedUnannotatedReadonlyField() throws Exception {
        var diags = PipelineTestSupport.diagnostics(source(""), "Meta.runar.ts");
        assertTrue(diags.warnings().stream().anyMatch(w ->
            w.contains("metadataId") && w.contains("eliminated by DCE") && w.contains("@embedAlways")),
            diags.warnings().toString());
    }

    @Test
    void doesNotWarnWhenFieldIsAnnotated() throws Exception {
        var diags = PipelineTestSupport.diagnostics(source("/** @embedAlways */"), "Meta.runar.ts");
        assertFalse(diags.warnings().stream().anyMatch(w -> w.contains("metadataId")),
            diags.warnings().toString());
    }

    @Test
    void doesNotWarnForReferencedReadonlyField() throws Exception {
        String referenced =
            "class P2PKH extends SmartContract {\n"
            + "  readonly pubKeyHash: Addr;\n"
            + "  constructor(pubKeyHash: Addr) { super(pubKeyHash); this.pubKeyHash = pubKeyHash; }\n"
            + "  public unlock(sig: Sig, pubKey: PubKey) {\n"
            + "    assert(hash160(pubKey) === this.pubKeyHash); assert(checkSig(sig, pubKey));\n"
            + "  }\n"
            + "}\n";
        var diags = PipelineTestSupport.diagnostics(referenced, "P2PKH.runar.ts");
        assertFalse(diags.warnings().stream().anyMatch(w -> w.contains("pubKeyHash")),
            diags.warnings().toString());
    }

    // ---- Regression: @embedAlways must survive a FIXED-POINT DCE -------------
    //
    // The preservation used to be an alias pair: the injected `load_prop` plus a
    // `load_const("@ref:<t>")` binding whose only job was to make the `load_prop`
    // look referenced. That survives ONE DCE sweep but not the fixed-point loop
    // in Dce: sweep 1 drops the now-unreferenced alias, sweep 2 then drops the
    // `load_prop` it was protecting, and BOTH halves vanish.
    //
    // DCE only runs from inside the EC optimizer's changed-gate, so the probe
    // has to arm it: `ecMulGen(1n)` folds to the generator constant, which flips
    // `changed` and lets dead-binding elimination run.
    //
    // Zig marks the injected `load_prop` itself with `preserve = true` and reads
    // that flag in `hasSideEffect`; this tier now does the same.

    /**
     * EC-armed probe. {@code metadataId} carries DIRECTIVE; {@code droppedField}
     * is an un-annotated, unreferenced control that MUST still be eliminated, so
     * a passing test cannot be satisfied by "retain everything".
     */
    private static String ecSource(String directive) {
        return "class EcMeta extends SmartContract {\n"
            + "  readonly pubKeyHash: Addr;\n"
            + "  " + directive + "\n"
            + "  readonly metadataId: ByteString;\n"
            + "  readonly droppedField: ByteString;\n"
            + "  constructor(pubKeyHash: Addr, metadataId: ByteString, droppedField: ByteString) {\n"
            + "    super(pubKeyHash, metadataId, droppedField);\n"
            + "    this.pubKeyHash = pubKeyHash; this.metadataId = metadataId; this.droppedField = droppedField;\n"
            + "  }\n"
            + "  public unlock(sig: Sig, pubKey: PubKey) {\n"
            + "    const g = ecMulGen(1n);\n"
            + "    assert(ecPointX(g) > 0n);\n"
            + "    assert(hash160(pubKey) === this.pubKeyHash); assert(checkSig(sig, pubKey));\n"
            + "  }\n"
            + "}\n";
    }

    @Test
    void ecArmedAnnotatedFieldSurvivesFixedPointDce() throws Exception {
        var slots = PipelineTestSupport.slotParamIndexes(ecSource("/** @embedAlways */"), "EcMeta.runar.ts");
        assertTrue(slots.contains(1),
            "@embedAlways metadataId (param 1) must survive fixed-point DCE, slots: " + slots);
    }

    @Test
    void ecArmedUnannotatedDeadFieldIsStillEliminated() throws Exception {
        // Control: the fix must not degenerate into "keep every load_prop".
        for (String directive : new String[] {"", "/** @embedAlways */"}) {
            var slots = PipelineTestSupport.slotParamIndexes(ecSource(directive), "EcMeta.runar.ts");
            assertFalse(slots.contains(2),
                "un-annotated droppedField (param 2) must stay eliminated, directive=" + directive);
        }
    }

    @Test
    void ecArmedAnnotatedHexCarriesMoreBytes() throws Exception {
        String plain = PipelineTestSupport.hex(ecSource(""), "EcMeta.runar.ts");
        String embed = PipelineTestSupport.hex(ecSource("/** @embedAlways */"), "EcMeta.runar.ts");
        assertNotEquals(plain, embed, "@embedAlways must change the EC-armed script");
        assertTrue(embed.length() > plain.length(),
            "annotated hex (" + embed.length() + ") must exceed un-annotated (" + plain.length() + ")");
    }
}

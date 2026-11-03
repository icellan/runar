package runar.compiler.frontend;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import runar.compiler.frontend.ParserDispatch.ParseException;

/**
 * Fail-closed guard for the author-facing comment directives {@code @sighash}
 * (#123) and {@code @embedAlways} (#109). After the #123/#109 Java port these
 * directives are honoured ONLY on the {@code .runar.ts} surface; the guard is
 * NARROWED to the other 8 surface formats, which still ignore comments and so
 * must reject the directives rather than silently drop them.
 */
class DirectiveGuardTest {

    @Test
    void rejectsSighashDirectiveInNonTsFormat() {
        String src =
            "class Counter extends SmartContract {\n"
            + "  readonly x: bigint;\n"
            + "  constructor(x: bigint) { super(x); this.x = x; }\n"
            + "  /** @sighash SINGLE|FORKID */\n"
            + "  public unlock() {}\n"
            + "}\n";
        ParseException ex = assertThrows(
            ParseException.class,
            () -> ParserDispatch.parse(src, "Counter.runar.go"));
        assertTrue(ex.getMessage().contains("@sighash"), ex.getMessage());
        assertTrue(ex.getMessage().contains("#123"), ex.getMessage());
    }

    @Test
    void rejectsEmbedAlwaysDirectiveInNonTsFormat() {
        String src =
            "class Counter extends SmartContract {\n"
            + "  /** @embedAlways */\n"
            + "  readonly x: bigint;\n"
            + "  constructor(x: bigint) { super(x); this.x = x; }\n"
            + "  public unlock() {}\n"
            + "}\n";
        ParseException ex = assertThrows(
            ParseException.class,
            () -> ParserDispatch.parse(src, "Counter.runar.rs"));
        assertTrue(ex.getMessage().contains("@embedAlways"), ex.getMessage());
        assertTrue(ex.getMessage().contains("#109"), ex.getMessage());
    }

    @Test
    void allowsDirectivesOnTheTsSurface() throws Exception {
        // Narrowed guard: the .runar.ts parser now honours the directives, so
        // the guard must NOT fire for a .runar.ts source.
        String sighash =
            "class Counter extends StatefulSmartContract {\n"
            + "  n: bigint;\n"
            + "  constructor(n: bigint) { super(n); this.n = n; }\n"
            + "  /** @sighash SINGLE|FORKID */\n"
            + "  public bump(): void { this.addOutput(1000n, this.n); }\n"
            + "}\n";
        // Parses cleanly (no guard ParseException).
        ParserDispatch.parse(sighash, "Counter.runar.ts");

        String embed =
            "class Meta extends SmartContract {\n"
            + "  readonly pubKeyHash: Addr;\n"
            + "  /** @embedAlways */\n"
            + "  readonly metadataId: ByteString;\n"
            + "  constructor(pubKeyHash: Addr, metadataId: ByteString) {\n"
            + "    super(pubKeyHash, metadataId); this.pubKeyHash = pubKeyHash; this.metadataId = metadataId;\n"
            + "  }\n"
            + "  public unlock(sig: Sig, pubKey: PubKey) {\n"
            + "    assert(hash160(pubKey) === this.pubKeyHash); assert(checkSig(sig, pubKey));\n"
            + "  }\n"
            + "}\n";
        ParserDispatch.parse(embed, "Meta.runar.ts");
    }

    @Test
    void doesNotTripOnNonDirectiveIdentifier() {
        // A field named `sighashType` (no `@`) must NOT trip the `@sighash` guard
        // in a non-TS format. The format parser may still raise its own errors; we
        // only assert the directive guard message is not the failure reason.
        String src =
            "class Counter extends SmartContract {\n"
            + "  readonly sighashType: bigint;\n"
            + "  constructor(sighashType: bigint) { super(sighashType); this.sighashType = sighashType; }\n"
            + "  public unlock() {}\n"
            + "}\n";
        try {
            ParserDispatch.parse(src, "Counter.runar.go");
        } catch (Exception e) {
            assertFalse(e.getMessage().contains("@sighash directive"),
                "directive guard tripped on a non-directive identifier: " + e.getMessage());
        }
    }
}

package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.frontend.JavaParser;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.ir.stack.RawBytesOp;
import runar.compiler.ir.stack.StackMethod;
import runar.compiler.ir.stack.StackOp;
import runar.compiler.ir.stack.StackProgram;
import runar.compiler.ir.stack.StackSourceLoc;

/**
 * F-316. {@code RawBytesOp} — the opaque opcode-byte span a {@code raw_script}
 * ANF node lowers to for an {@code asm({...})} call — carried no {@code
 * sourceLoc} field. {@code StackLower#stampSourceLoc} explicitly skipped it
 * ("RawBytesOp has no sourceLoc field — skip.") and {@code
 * Emit#extractSourceLoc} explicitly returned {@code null} for it, so a
 * located {@code asm} statement produced no source-map entry at all — the
 * only {@code StackOp} variant with that gap. The TS reference does not have
 * this gap: {@code RawBytesOp} there has carried a {@code sourceLoc} field
 * since 05-stack-lower.ts's generic {@code emitOp} stamps every emitted op,
 * `asm` spans included (confirmed by compiling the `asm-raw-script` example
 * through the TS compiler and inspecting `artifact.sourceMap`: one entry at
 * opcodeIndex 0 for the one-byte raw span).
 */
class F316RawBytesSourceMapTest {

    private static final String ANYONE_JAVA_SRC = """
        package runar.examples.asm_raw_script;

        import runar.lang.UnsafeSmartContract;
        import runar.lang.annotations.Public;
        import static runar.lang.Builtins.asm;

        class Anyone extends UnsafeSmartContract {
            Anyone() {
                super();
            }

            @Public
            void unlock() {
                asm("51", 0, 1);
            }
        }
        """;

    /**
     * End-to-end: parse the `asm-raw-script` example's Java-format source
     * (the body of `unlock()` is a single located `asm(...)` call), run it
     * through the full Java compiler pipeline, and request the source map.
     *
     * What this proves: the located `asm` statement — which lowers to a
     * single opaque `raw_script` ANF node, then a single `RawBytesOp` — now
     * produces a source-map entry whose opcodeIndex is the raw span's
     * opcode index (0, since it's the method's only op), matching the TS
     * reference's behaviour for the same example.
     *
     * What this does NOT prove: multi-statement methods where a raw_script
     * binding sits among other bindings (covered by the opcode-index algebra
     * already exercised for other op kinds in R084PlaceholderOpcodeIndexTest),
     * or that every one of the 7 tiers matches (this item is Java-tier only;
     * Stack IR is compiler-local and not part of the cross-tier conformance
     * boundary per CLAUDE.md).
     */
    @Test
    void locatedAsmStatementProducesASourceMapEntry() {
        ContractNode c = JavaParser.parse(ANYONE_JAVA_SRC, "Anyone.runar.java");
        Validate.run(c);
        Typecheck.run(c);
        AnfProgram anf = AnfLower.run(c);
        StackProgram stack = StackLower.run(anf);

        // Sanity: the method lowers to exactly one RawBytesOp, and it must
        // carry a sourceLoc once the fix lands (this is the failing
        // assertion before the fix: RawBytesOp had no sourceLoc() accessor
        // at all, so this wouldn't even compile against the pre-fix record;
        // against the fixed record it must be non-null).
        StackMethod unlock = findMethod(stack, "unlock");
        RawBytesOp rawOp = findOnlyRawBytesOp(unlock.ops());
        assertTrue(rawOp.sourceLoc() != null,
            "a RawBytesOp lowered from a located asm() call must carry a sourceLoc");
        assertEquals("Anyone.runar.java", rawOp.sourceLoc().file());

        Emit.EmitResultFull full = Emit.runResultFull(stack);
        List<Emit.SourceMapping> unlockMappings = full.sourceMap();
        assertTrue(!unlockMappings.isEmpty(),
            "a located asm() raw_script span must produce at least one source-map entry");
        // The single raw_bytes opcode is this method's opcode 0 (the
        // dispatcher preamble lives in a different method's op list, but
        // this contract has only one public method so there is no dispatch
        // preamble at all — the emitted script IS the raw byte).
        assertEquals(0, unlockMappings.get(0).opcodeIndex());
        assertEquals("Anyone.runar.java", unlockMappings.get(0).sourceFile());
    }

    /**
     * Unit-level control, independent of the parser/AnfLower: a RawBytesOp
     * built directly with a StackSourceLoc must round-trip through Emit
     * into a source-map entry, exactly like every other StackOp variant
     * (mirrors the style of R084PlaceholderOpcodeIndexTest).
     */
    @Test
    void rawBytesOpCarryingASourceLocRecordsItsOwnMapping() {
        StackSourceLoc loc = new StackSourceLoc("C.runar.ts", 11, 4);
        StackProgram program = new StackProgram("T", List.of(new StackMethod(
            "unlock",
            List.of(new RawBytesOp(new byte[] {0x51}, 0, 1, loc)),
            0L)));

        Emit.EmitResultFull r = Emit.runResultFull(program);

        assertEquals(1, r.sourceMap().size());
        assertEquals(0, r.sourceMap().get(0).opcodeIndex());
        assertEquals(11, r.sourceMap().get(0).line());
        assertEquals("51", r.scriptHex());
    }

    private static StackMethod findMethod(StackProgram program, String name) {
        for (StackMethod m : program.methods()) {
            if (m.name().equals(name)) return m;
        }
        throw new AssertionError("no method named '" + name + "' in lowered program");
    }

    private static RawBytesOp findOnlyRawBytesOp(List<StackOp> ops) {
        RawBytesOp found = null;
        for (StackOp op : ops) {
            if (op instanceof RawBytesOp rb) {
                assertTrue(found == null, "expected exactly one RawBytesOp");
                found = rb;
            }
        }
        assertTrue(found != null, "expected exactly one RawBytesOp");
        return found;
    }
}

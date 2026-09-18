package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.ir.stack.OpcodeOp;
import runar.compiler.ir.stack.PlaceholderOp;
import runar.compiler.ir.stack.PushCodeSepIndexOp;
import runar.compiler.ir.stack.StackMethod;
import runar.compiler.ir.stack.StackOp;
import runar.compiler.ir.stack.StackProgram;
import runar.compiler.ir.stack.StackSourceLoc;

/**
 * R-084. The {@code 00} written for a {@code placeholder} / {@code
 * push_codesep_index} op is the deploy-time placeholder byte by design, and the
 * real value travels beside it in {@code constructorSlots} / {@code
 * codeSepIndexSlots} — that part of the finding is refuted, and the slot tables
 * are pinned below to keep it refuted.
 *
 * <p>What is real: both placeholders occupy one opcode in the emitted script,
 * and every other tier's emitter says so — TS {@code emitPlaceholder} /
 * {@code emitCodeSepIndexPlaceholder} (06-emit.ts:337/399), Go
 * {@code emitPlaceholder} / the {@code push_codesep_index} case
 * (codegen/emit.go:270/621), Rust (codegen/emit.rs:189/518), Python
 * (codegen/emit.py:244/539), Zig (codegen/emit.zig:367/384) and Ruby
 * (codegen/emit.rb:444/488) all call their {@code recordSourceMapping} and then
 * advance the opcode index. Java advanced neither, so a script containing a
 * placeholder handed out a {@code sourceMap} whose {@code opcodeIndex} pointed
 * one opcode short — for every mapping after it — and a placeholder that
 * carried its own {@code sourceLoc} produced no mapping at all.
 *
 * <p>The emitted bytes never depended on the counter, so the hex controls below
 * must not move.
 */
class R084PlaceholderOpcodeIndexTest {

    private static final StackSourceLoc BEFORE = new StackSourceLoc("C.runar.ts", 10, 4);
    private static final StackSourceLoc AT = new StackSourceLoc("C.runar.ts", 11, 4);
    private static final StackSourceLoc AFTER = new StackSourceLoc("C.runar.ts", 12, 4);

    private static StackProgram singleMethod(List<StackOp> ops) {
        return new StackProgram("T", List.of(new StackMethod("unlock", ops, 0L)));
    }

    // ------------------------------------------------------------------
    // opcode index: a placeholder occupies an opcode slot
    // ------------------------------------------------------------------

    @Test
    void constructorPlaceholderAdvancesTheOpcodeIndex() {
        Emit.EmitResultFull r = Emit.runResultFull(singleMethod(List.of(
            new OpcodeOp("OP_DUP", BEFORE),
            new PlaceholderOp(0L, "owner"),
            new OpcodeOp("OP_DROP", AFTER))));

        // OP_DUP is opcode 0, the placeholder is opcode 1, OP_DROP is opcode 2.
        assertEquals(List.of(0, 2), opcodeIndices(r.sourceMap()),
            "a constructor placeholder must occupy one opcode index, as it does "
                + "in the six peer emitters");
        // Control: the bytes are unchanged — 76 (OP_DUP) 00 (placeholder) 75 (OP_DROP).
        assertEquals("760075", r.scriptHex());
        assertEquals(1, r.constructorSlots().size());
        assertEquals(1, r.constructorSlots().get(0).byteOffset());
    }

    @Test
    void codeSepIndexPlaceholderAdvancesTheOpcodeIndex() {
        Emit.EmitResultFull r = Emit.runResultFull(singleMethod(List.of(
            new OpcodeOp("OP_DUP", BEFORE),
            new PushCodeSepIndexOp(),
            new OpcodeOp("OP_DROP", AFTER))));

        assertEquals(List.of(0, 2), opcodeIndices(r.sourceMap()),
            "a codeSepIndex placeholder must occupy one opcode index, as it does "
                + "in the six peer emitters");
        assertEquals("760075", r.scriptHex());
        assertEquals(1, r.codeSepIndexSlots().size());
        assertEquals(1, r.codeSepIndexSlots().get(0).byteOffset());
    }

    @Test
    void everyMappingAfterTwoPlaceholdersShiftsByTwo() {
        Emit.EmitResultFull r = Emit.runResultFull(singleMethod(List.of(
            new OpcodeOp("OP_DUP", BEFORE),
            new PlaceholderOp(0L, "owner"),
            new PushCodeSepIndexOp(),
            new OpcodeOp("OP_DROP", AFTER),
            new OpcodeOp("OP_NIP", AFTER))));

        assertEquals(List.of(0, 3, 4), opcodeIndices(r.sourceMap()));
        assertEquals("7600007577", r.scriptHex());
    }

    // ------------------------------------------------------------------
    // source mapping: a placeholder that carries a loc must produce one
    // ------------------------------------------------------------------

    @Test
    void aPlaceholderCarryingASourceLocRecordsItsOwnMapping() {
        Emit.EmitResultFull r = Emit.runResultFull(singleMethod(List.of(
            new OpcodeOp("OP_DUP", BEFORE),
            new PlaceholderOp(java.math.BigInteger.ZERO, "owner", AT),
            new OpcodeOp("OP_DROP", AFTER))));

        assertEquals(List.of(0, 1, 2), opcodeIndices(r.sourceMap()));
        assertEquals(11, r.sourceMap().get(1).line());
        assertEquals("760075", r.scriptHex());
    }

    @Test
    void aCodeSepIndexPlaceholderCarryingASourceLocRecordsItsOwnMapping() {
        Emit.EmitResultFull r = Emit.runResultFull(singleMethod(List.of(
            new OpcodeOp("OP_DUP", BEFORE),
            new PushCodeSepIndexOp(AT),
            new OpcodeOp("OP_DROP", AFTER))));

        assertEquals(List.of(0, 1, 2), opcodeIndices(r.sourceMap()));
        assertEquals(11, r.sourceMap().get(1).line());
        assertEquals("760075", r.scriptHex());
    }

    // ------------------------------------------------------------------
    // the refuted half: the placeholder byte and the recorded index
    // ------------------------------------------------------------------

    @Test
    void theCodeSepIndexSlotCarriesTheMostRecentSeparatorNotTheByteWritten() {
        // OP_NOP, OP_CODESEPARATOR (offset 1), then the placeholder. The byte
        // written is the 00 placeholder; the slot carries the separator's
        // offset, which is what the SDK back-patches in. Identical to the Go
        // tier's `codeSepIdx := ctx.codeSeparatorIndex` + `appendHex("00")`.
        Emit.EmitResultFull r = Emit.runResultFull(singleMethod(List.of(
            new OpcodeOp("OP_NOP"),
            new OpcodeOp("OP_CODESEPARATOR"),
            new PushCodeSepIndexOp())));

        assertEquals("61ab00", r.scriptHex());
        assertEquals(1, r.codeSeparatorIndex());
        assertEquals(1, r.codeSepIndexSlots().size());
        assertEquals(2, r.codeSepIndexSlots().get(0).byteOffset());
        assertEquals(1, r.codeSepIndexSlots().get(0).codeSepIndex());
    }

    private static List<Integer> opcodeIndices(List<Emit.SourceMapping> mappings) {
        return mappings.stream().map(Emit.SourceMapping::opcodeIndex).toList();
    }
}

package runar.compiler.ir.stack;

import java.math.BigInteger;
import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.canonical.Jcs;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Covers the canonical-JSON shape of every Stack IR variant.
 * Expected strings are hand-computed to match the TS schema
 * ({@code packages/runar-ir-schema/src/stack-ir.ts}) when serialised
 * through {@code canonicalJsonStringify}.
 *
 * <p>Keys are sorted UTF-16 code-unit order (so {@code "else"} comes
 * before {@code "op"}, {@code "op"} before {@code "then"}, etc.), and
 * {@code sourceLoc} is omitted whenever {@code null}.
 */
class StackIrTest {

    // ---------------------------------------------------------------
    // Push variants
    // ---------------------------------------------------------------

    @Test
    void pushBigIntEmitsBareIntegerValue() {
        PushOp op = new PushOp(PushValue.of(7));
        assertEquals("{\"op\":\"push\",\"value\":7}", Jcs.stringify(op));
    }

    @Test
    void pushNegativeBigIntEmitsSignedInteger() {
        PushOp op = new PushOp(PushValue.of(BigInteger.valueOf(-1)));
        assertEquals("{\"op\":\"push\",\"value\":-1}", Jcs.stringify(op));
    }

    @Test
    void pushBooleanEmitsJsonBoolean() {
        assertEquals("{\"op\":\"push\",\"value\":true}", Jcs.stringify(new PushOp(PushValue.of(true))));
        assertEquals("{\"op\":\"push\",\"value\":false}", Jcs.stringify(new PushOp(PushValue.of(false))));
    }

    @Test
    void pushByteStringEmitsHexStringValue() {
        PushOp op = new PushOp(PushValue.ofHex("deadbeef"));
        assertEquals("{\"op\":\"push\",\"value\":\"deadbeef\"}", Jcs.stringify(op));
    }

    // ---------------------------------------------------------------
    // Nullary / parameterless ops
    // ---------------------------------------------------------------

    @Test
    void dupSerializesWithOnlyOp() {
        assertEquals("{\"op\":\"dup\"}", Jcs.stringify(new DupOp()));
    }

    @Test
    void swapSerializesWithOnlyOp() {
        assertEquals("{\"op\":\"swap\"}", Jcs.stringify(new SwapOp()));
    }

    @Test
    void dropSerializesWithOnlyOp() {
        assertEquals("{\"op\":\"drop\"}", Jcs.stringify(new DropOp()));
    }

    @Test
    void nipSerializesWithOnlyOp() {
        assertEquals("{\"op\":\"nip\"}", Jcs.stringify(new NipOp()));
    }

    @Test
    void overSerializesWithOnlyOp() {
        assertEquals("{\"op\":\"over\"}", Jcs.stringify(new OverOp()));
    }

    @Test
    void rotSerializesWithOnlyOp() {
        assertEquals("{\"op\":\"rot\"}", Jcs.stringify(new RotOp()));
    }

    @Test
    void tuckSerializesWithOnlyOp() {
        assertEquals("{\"op\":\"tuck\"}", Jcs.stringify(new TuckOp()));
    }

    @Test
    void pushCodeSepIndexSerializesWithOnlyOp() {
        assertEquals("{\"op\":\"push_codesep_index\"}", Jcs.stringify(new PushCodeSepIndexOp()));
    }

    // ---------------------------------------------------------------
    // Depth-carrying ops
    // ---------------------------------------------------------------

    @Test
    void rollSerializesWithDepth() {
        assertEquals("{\"depth\":2,\"op\":\"roll\"}", Jcs.stringify(new RollOp(2)));
    }

    @Test
    void pickSerializesWithDepth() {
        assertEquals("{\"depth\":5,\"op\":\"pick\"}", Jcs.stringify(new PickOp(5)));
    }

    // ---------------------------------------------------------------
    // Opcode
    // ---------------------------------------------------------------

    @Test
    void opcodeSerializesWithCode() {
        OpcodeOp op = new OpcodeOp("OP_ADD");
        assertEquals("{\"code\":\"OP_ADD\",\"op\":\"opcode\"}", Jcs.stringify(op));
    }

    @Test
    void opcodeSerializesChecksigLiterally() {
        OpcodeOp op = new OpcodeOp("OP_CHECKSIG");
        assertEquals("{\"code\":\"OP_CHECKSIG\",\"op\":\"opcode\"}", Jcs.stringify(op));
    }

    // ---------------------------------------------------------------
    // If (nested, with and without else)
    // ---------------------------------------------------------------

    @Test
    void ifWithoutElseOmitsElseKey() {
        IfOp op = new IfOp(List.of(new DupOp()));
        // Keys sorted: else (omitted when null), op, then
        assertEquals("{\"op\":\"if\",\"then\":[{\"op\":\"dup\"}]}", Jcs.stringify(op));
    }

    @Test
    void ifWithElseEmitsBothBranches() {
        IfOp op = new IfOp(
            List.of(new PushOp(PushValue.of(1))),
            List.of(new PushOp(PushValue.of(0)))
        );
        // UTF-16 order: "else" (e=0x65) < "op" (o=0x6f) < "then" (t=0x74)
        assertEquals(
            "{\"else\":[{\"op\":\"push\",\"value\":0}],\"op\":\"if\",\"then\":[{\"op\":\"push\",\"value\":1}]}",
            Jcs.stringify(op)
        );
    }

    @Test
    void nestedIfSerializesRecursively() {
        // if (then=[if (then=[dup], else=[drop])], else=[rot])
        IfOp inner = new IfOp(List.of(new DupOp()), List.of(new DropOp()));
        IfOp outer = new IfOp(List.of(inner), List.of(new RotOp()));
        assertEquals(
            "{\"else\":[{\"op\":\"rot\"}],\"op\":\"if\",\"then\":["
                + "{\"else\":[{\"op\":\"drop\"}],\"op\":\"if\",\"then\":[{\"op\":\"dup\"}]}"
                + "]}",
            Jcs.stringify(outer)
        );
    }

    @Test
    void ifWithEmptyBranchesSerializes() {
        IfOp op = new IfOp(List.of(), List.of());
        assertEquals("{\"else\":[],\"op\":\"if\",\"then\":[]}", Jcs.stringify(op));
    }

    // ---------------------------------------------------------------
    // Placeholder
    // ---------------------------------------------------------------

    @Test
    void placeholderSerializesAllFields() {
        PlaceholderOp op = new PlaceholderOp(0, "pubKeyHash");
        // Keys sorted: op, paramIndex, paramName (UTF-16 order:
        // paramIndex "I"=0x49 before paramName "N"=0x4e)
        assertEquals(
            "{\"op\":\"placeholder\",\"paramIndex\":0,\"paramName\":\"pubKeyHash\"}",
            Jcs.stringify(op)
        );
    }

    @Test
    void placeholderWithLargerIndexSerializes() {
        PlaceholderOp op = new PlaceholderOp(42, "amount");
        assertEquals(
            "{\"op\":\"placeholder\",\"paramIndex\":42,\"paramName\":\"amount\"}",
            Jcs.stringify(op)
        );
    }

    // ---------------------------------------------------------------
    // sourceLoc omission
    // ---------------------------------------------------------------

    @Test
    void nullSourceLocIsOmitted() {
        DupOp op = new DupOp(null);
        assertEquals("{\"op\":\"dup\"}", Jcs.stringify(op));
    }

    @Test
    void presentSourceLocIsEmitted() {
        DupOp op = new DupOp(new StackSourceLoc("Counter.runar.ts", 12, 4));
        // Key order: column < file < line
        assertEquals(
            "{\"op\":\"dup\",\"sourceLoc\":{\"column\":4,\"file\":\"Counter.runar.ts\",\"line\":12}}",
            Jcs.stringify(op)
        );
    }

    // ---------------------------------------------------------------
    // End-to-end: a tiny StackProgram
    // ---------------------------------------------------------------

    @Test
    void minimalStackProgramSerializes() {
        // A handful of ops exercising push (bigint + bytestring),
        // opcode, if, placeholder, and nullary ops — nested into one
        // StackMethod, wrapped in a StackProgram.
        StackOp op0 = new PushOp(PushValue.ofHex("cafebabe"));
        StackOp op1 = new DupOp();
        StackOp op2 = new OpcodeOp("OP_HASH160");
        StackOp op3 = new PlaceholderOp(0, "pubKeyHash");
        StackOp op4 = new IfOp(
            List.of(new PushOp(PushValue.of(true))),
            List.of(new PushOp(PushValue.of(false)))
        );
        StackOp op5 = new OpcodeOp("OP_CHECKSIG");

        StackMethod unlock = new StackMethod(
            "unlock",
            List.of(op0, op1, op2, op3, op4, op5),
            4L
        );

        StackProgram program = new StackProgram("P2PKH", List.of(unlock));

        // contractName < methods. Inside method: maxStackDepth < name < ops.
        assertEquals(
            "{\"contractName\":\"P2PKH\","
                + "\"methods\":[{"
                + "\"maxStackDepth\":4,"
                + "\"name\":\"unlock\","
                + "\"ops\":["
                + "{\"op\":\"push\",\"value\":\"cafebabe\"},"
                + "{\"op\":\"dup\"},"
                + "{\"code\":\"OP_HASH160\",\"op\":\"opcode\"},"
                + "{\"op\":\"placeholder\",\"paramIndex\":0,\"paramName\":\"pubKeyHash\"},"
                + "{\"else\":[{\"op\":\"push\",\"value\":false}],\"op\":\"if\",\"then\":[{\"op\":\"push\",\"value\":true}]},"
                + "{\"code\":\"OP_CHECKSIG\",\"op\":\"opcode\"}"
                + "]"
                + "}]}",
            Jcs.stringify(program)
        );
    }

    @Test
    void emptyStackProgramSerializes() {
        StackProgram program = new StackProgram("Empty", List.of());
        assertEquals("{\"contractName\":\"Empty\",\"methods\":[]}", Jcs.stringify(program));
    }
}

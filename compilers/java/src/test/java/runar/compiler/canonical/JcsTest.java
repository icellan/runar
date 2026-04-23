package runar.compiler.canonical;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import runar.compiler.ir.anf.AnfBinding;
import runar.compiler.ir.anf.AnfMethod;
import runar.compiler.ir.anf.AnfParam;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.anf.AnfProperty;
import runar.compiler.ir.anf.Assert;
import runar.compiler.ir.anf.BinOp;
import runar.compiler.ir.anf.Call;
import runar.compiler.ir.anf.ConstValue;
import runar.compiler.ir.anf.LoadConst;
import runar.compiler.ir.anf.LoadParam;
import runar.compiler.ir.anf.LoadProp;
import runar.compiler.ir.stack.DupOp;
import runar.compiler.ir.stack.OpcodeOp;
import runar.compiler.ir.stack.PushOp;
import runar.compiler.ir.stack.PushValue;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Covers the JCS contract required by the Rúnar conformance boundary.
 * Expected strings are hand-computed to match the output of
 * {@code packages/runar-ir-schema/src/canonical-json.ts} for the same
 * input structures.
 */
class JcsTest {

    // ---------------------------------------------------------------
    // Primitives
    // ---------------------------------------------------------------

    @Test
    void nullSerializes() {
        assertEquals("null", Jcs.stringify(null));
    }

    @Test
    void booleansSerialize() {
        assertEquals("true", Jcs.stringify(Boolean.TRUE));
        assertEquals("false", Jcs.stringify(Boolean.FALSE));
    }

    @Test
    void bigIntegersSerializeAsBareIntegers() {
        assertEquals("0", Jcs.stringify(BigInteger.ZERO));
        assertEquals("1", Jcs.stringify(BigInteger.ONE));
        assertEquals("-42", Jcs.stringify(BigInteger.valueOf(-42)));
        // Beyond JS Number.MAX_SAFE_INTEGER: still bare integer.
        assertEquals(
            "123456789012345678901234567890",
            Jcs.stringify(new BigInteger("123456789012345678901234567890"))
        );
    }

    @Test
    void stringsEscapeStandardControlCharacters() {
        assertEquals("\"\"", Jcs.stringify(""));
        assertEquals("\"hello\"", Jcs.stringify("hello"));
        assertEquals("\"\\\"\"", Jcs.stringify("\""));
        assertEquals("\"\\\\\"", Jcs.stringify("\\"));
        assertEquals("\"\\b\"", Jcs.stringify("\b"));
        assertEquals("\"\\f\"", Jcs.stringify("\f"));
        assertEquals("\"\\n\"", Jcs.stringify("\n"));
        assertEquals("\"\\r\"", Jcs.stringify("\r"));
        assertEquals("\"\\t\"", Jcs.stringify("\t"));
    }

    @Test
    void stringsEscapeLowControlCharactersAsUnicode() {
        // U+0001 → 
        assertEquals("\"\\u0001\"", Jcs.stringify(""));
        // U+001F →  (lowercase hex, per JSON.stringify)
        assertEquals("\"\\u001f\"", Jcs.stringify(""));
    }

    @Test
    void stringsDoNotEscapeSolidus() {
        // JSON.stringify does not escape '/'.
        assertEquals("\"a/b\"", Jcs.stringify("a/b"));
    }

    @Test
    void stringsEmitNonAsciiCharactersLiterally() {
        // U+00A9 (copyright) and U+1F600 (emoji as surrogate pair) pass through.
        assertEquals("\"©\"", Jcs.stringify("©"));
        assertEquals("\"😀\"", Jcs.stringify("😀"));
    }

    @Test
    void doubleThrows() {
        assertThrows(IllegalArgumentException.class, () -> Jcs.stringify(1.5));
    }

    // ---------------------------------------------------------------
    // Arrays
    // ---------------------------------------------------------------

    @Test
    void emptyArraySerializes() {
        assertEquals("[]", Jcs.stringify(List.of()));
    }

    @Test
    void arrayOfStringsSerializes() {
        assertEquals("[\"a\",\"b\",\"c\"]", Jcs.stringify(List.of("a", "b", "c")));
    }

    @Test
    void arrayOfMixedTypesSerializes() {
        assertEquals(
            "[true,1,\"x\"]",
            Jcs.stringify(List.of(Boolean.TRUE, BigInteger.ONE, "x"))
        );
    }

    // ---------------------------------------------------------------
    // Objects (Map)
    // ---------------------------------------------------------------

    @Test
    void emptyMapSerializes() {
        assertEquals("{}", Jcs.stringify(Map.of()));
    }

    @Test
    void mapKeysSortByUtf16CodeUnitOrder() {
        // Insertion order is b, a, c — serialization must be a, b, c.
        var m = new java.util.LinkedHashMap<String, Object>();
        m.put("b", BigInteger.ONE);
        m.put("a", BigInteger.ZERO);
        m.put("c", BigInteger.TWO);
        assertEquals("{\"a\":0,\"b\":1,\"c\":2}", Jcs.stringify(m));
    }

    @Test
    void mapOmitsNullValuedKeys() {
        var m = new java.util.LinkedHashMap<String, Object>();
        m.put("a", "present");
        m.put("b", null);
        m.put("c", BigInteger.ONE);
        assertEquals("{\"a\":\"present\",\"c\":1}", Jcs.stringify(m));
    }

    @Test
    void nestedMapsSortIndependently() {
        var inner = new java.util.LinkedHashMap<String, Object>();
        inner.put("y", BigInteger.TWO);
        inner.put("x", BigInteger.ONE);
        var outer = new java.util.LinkedHashMap<String, Object>();
        outer.put("b", inner);
        outer.put("a", BigInteger.ZERO);
        assertEquals("{\"a\":0,\"b\":{\"x\":1,\"y\":2}}", Jcs.stringify(outer));
    }

    // ---------------------------------------------------------------
    // Records with kind() injection
    // ---------------------------------------------------------------

    @Test
    void loadParamRecordEmitsKindAndComponents() {
        // Expected: {"kind":"load_param","name":"sig"}
        assertEquals("{\"kind\":\"load_param\",\"name\":\"sig\"}", Jcs.stringify(new LoadParam("sig")));
    }

    @Test
    void binOpSkipsNullResultType() {
        // resultType is null → omitted
        BinOp op = new BinOp("+", "t0", "t1", null);
        assertEquals("{\"kind\":\"bin_op\",\"left\":\"t0\",\"op\":\"+\",\"right\":\"t1\"}", Jcs.stringify(op));
    }

    @Test
    void binOpEmitsResultTypeWhenPresent() {
        BinOp op = new BinOp("===", "t0", "t1", "bytes");
        assertEquals(
            "{\"kind\":\"bin_op\",\"left\":\"t0\",\"op\":\"===\",\"result_type\":\"bytes\",\"right\":\"t1\"}",
            Jcs.stringify(op)
        );
    }

    @Test
    void loadConstEmitsRawBigIntValue() {
        LoadConst c = new LoadConst(ConstValue.of(7));
        assertEquals("{\"kind\":\"load_const\",\"value\":7}", Jcs.stringify(c));
    }

    @Test
    void loadConstEmitsRawBooleanValue() {
        LoadConst c = new LoadConst(ConstValue.of(true));
        assertEquals("{\"kind\":\"load_const\",\"value\":true}", Jcs.stringify(c));
    }

    @Test
    void loadConstEmitsRawHexStringValue() {
        LoadConst c = new LoadConst(ConstValue.ofHex("deadbeef"));
        assertEquals("{\"kind\":\"load_const\",\"value\":\"deadbeef\"}", Jcs.stringify(c));
    }

    @Test
    void callRecordEmitsArgsArray() {
        Call call = new Call("hash160", List.of("t0"));
        assertEquals(
            "{\"args\":[\"t0\"],\"func\":\"hash160\",\"kind\":\"call\"}",
            Jcs.stringify(call)
        );
    }

    @Test
    void assertRecordEmitsValueRef() {
        Assert a = new Assert("t3");
        assertEquals("{\"kind\":\"assert\",\"value\":\"t3\"}", Jcs.stringify(a));
    }

    // ---------------------------------------------------------------
    // Records with op() injection (Stack IR convention)
    // ---------------------------------------------------------------

    @Test
    void dupOpEmitsOpDiscriminatorOnly() {
        // Confirms the op() reflection injection used by Stack IR
        // variants, analogous to kind() for ANF IR.
        assertEquals("{\"op\":\"dup\"}", Jcs.stringify(new DupOp()));
    }

    @Test
    void opcodeOpEmitsOpDiscriminatorAndComponents() {
        assertEquals(
            "{\"code\":\"OP_ADD\",\"op\":\"opcode\"}",
            Jcs.stringify(new OpcodeOp("OP_ADD"))
        );
    }

    @Test
    void pushOpEmitsRawPushValuePayload() {
        // Confirms PushValue dispatch (parallel to ConstValue).
        assertEquals(
            "{\"op\":\"push\",\"value\":7}",
            Jcs.stringify(new PushOp(PushValue.of(7)))
        );
    }

    // ---------------------------------------------------------------
    // End-to-end: a tiny AnfProgram
    // ---------------------------------------------------------------

    @Test
    void minimalAnfProgramSerializes() {
        // Equivalent to a P2PKH-like shape with one readonly property and
        // one public method.
        AnfProperty prop = new AnfProperty("pubKeyHash", "Addr", true, null);

        AnfBinding b0 = new AnfBinding("t0", new LoadParam("pubKey"), null);
        AnfBinding b1 = new AnfBinding("t1", new Call("hash160", List.of("t0")), null);
        AnfBinding b2 = new AnfBinding("t2", new LoadProp("pubKeyHash"), null);
        AnfBinding b3 = new AnfBinding("t3", new BinOp("===", "t1", "t2", "bytes"), null);
        AnfBinding b4 = new AnfBinding("_", new Assert("t3"), null);

        AnfMethod unlock = new AnfMethod(
            "unlock",
            List.of(new AnfParam("sig", "Sig"), new AnfParam("pubKey", "PubKey")),
            List.of(b0, b1, b2, b3, b4),
            true
        );

        AnfProgram program = new AnfProgram("P2PKH", List.of(prop), List.of(unlock));

        String json = Jcs.stringify(program);
        // Spot-check key structural invariants; full TS-parity check is an M4
        // conformance-runner concern.
        assertEquals(
            "{\"contractName\":\"P2PKH\"," +
                "\"methods\":[" +
                    "{\"body\":[" +
                        "{\"name\":\"t0\",\"value\":{\"kind\":\"load_param\",\"name\":\"pubKey\"}}," +
                        "{\"name\":\"t1\",\"value\":{\"args\":[\"t0\"],\"func\":\"hash160\",\"kind\":\"call\"}}," +
                        "{\"name\":\"t2\",\"value\":{\"kind\":\"load_prop\",\"name\":\"pubKeyHash\"}}," +
                        "{\"name\":\"t3\",\"value\":{\"kind\":\"bin_op\",\"left\":\"t1\",\"op\":\"===\"," +
                            "\"result_type\":\"bytes\",\"right\":\"t2\"}}," +
                        "{\"name\":\"_\",\"value\":{\"kind\":\"assert\",\"value\":\"t3\"}}" +
                    "]," +
                    "\"isPublic\":true," +
                    "\"name\":\"unlock\"," +
                    "\"params\":[" +
                        "{\"name\":\"sig\",\"type\":\"Sig\"}," +
                        "{\"name\":\"pubKey\",\"type\":\"PubKey\"}" +
                    "]}" +
                "]," +
                "\"properties\":[" +
                    "{\"name\":\"pubKeyHash\",\"readonly\":true,\"type\":\"Addr\"}" +
                "]}",
            json
        );
    }

    // ---------------------------------------------------------------
    // Cycle detection
    // ---------------------------------------------------------------

    @Test
    void circularListThrows() {
        List<Object> a = new java.util.ArrayList<>();
        a.add(a);
        assertThrows(IllegalArgumentException.class, () -> Jcs.stringify(a));
    }
}

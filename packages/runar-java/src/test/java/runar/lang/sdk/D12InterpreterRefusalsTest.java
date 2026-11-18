package runar.lang.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * D12 BM-F4 / BM-F5 / reverseBytes: the SDK ANF interpreter must compute what
 * the compiled script computes, or refuse -- never invent a value.
 * <ul>
 *   <li>ByteString {@code & | ^} returned "" (script: OP_AND/OP_OR/OP_XOR on
 *       equal-length operands, abort on a mismatch). Now exact.</li>
 *   <li>{@code int2str} and any unmodelled builtin returned null. int2str is
 *       now OP_NUM2BIN; an unmodelled builtin is refused.</li>
 *   <li>{@code num2bin} truncated a value too wide for the field and returned
 *       "" for a negative width (script: OP_NUM2BIN aborts). Now refused.</li>
 *   <li>{@code reverseBytes} reversed every byte; the script reverses only the
 *       first 520. Inputs over 520 bytes are refused.</li>
 * </ul>
 * Proves: those values / refusals at the interpreter's evaluation functions.
 * Does not prove: script execution (Java ships no ScriptVM).
 */
class D12InterpreterRefusalsTest {

    private static Object call(String func, Object... args) {
        return AnfInterpreter.evalCall(func, List.of(args), null, null);
    }

    private static Object bin(String op, String l, String r) {
        return AnfInterpreter.evalBinOp(op, l, r, "bytes");
    }

    @Test
    void bytesBitwiseIsExact() {
        assertEquals("0f", bin("&", "ff", "0f"));
        assertEquals("ff", bin("|", "f0", "0f"));
        assertEquals("f000", bin("^", "ff0f", "0f0f"));
    }

    @Test
    void bytesBitwiseLengthMismatchRefused() {
        for (String op : List.of("&", "|", "^")) {
            assertThrows(RuntimeException.class, () -> bin(op, "ff", "ffff"), op);
        }
    }

    @Test
    void int2strIsNum2bin() {
        assertEquals("0500", call("int2str", BigInteger.valueOf(5), BigInteger.valueOf(2)));
        assertEquals("0180", call("int2str", BigInteger.valueOf(-1), BigInteger.valueOf(2)));
    }

    @Test
    void unknownBuiltinRefused() {
        RuntimeException e = assertThrows(RuntimeException.class, () -> call("noSuchBuiltin", BigInteger.ONE));
        assertTrue(e.getMessage().contains("noSuchBuiltin"), e.getMessage());
    }

    @Test
    void num2binNarrowOrNegativeWidthRefused() {
        long[][] cases = {{40000, 2}, {128, 1}, {1L << 31, 4}, {1, 0}, {5, -1}, {0, -1}};
        for (String f : List.of("num2bin", "int2str")) {
            for (long[] c : cases) {
                assertThrows(RuntimeException.class,
                    () -> call(f, BigInteger.valueOf(c[0]), BigInteger.valueOf(c[1])), f + "(" + c[0] + ", " + c[1] + ")");
            }
            assertThrows(RuntimeException.class,
                () -> call(f, BigInteger.ONE.shiftLeft(63), BigInteger.valueOf(8)), f + "(2^63, 8)");
        }
        assertEquals("", call("num2bin", BigInteger.ZERO, BigInteger.ZERO));
        assertEquals("ff00", call("num2bin", BigInteger.valueOf(255), BigInteger.valueOf(2)));
    }

    @Test
    void reverseBytesBoundedAt520() {
        assertEquals("00".repeat(519) + "01", call("reverseBytes", "01" + "00".repeat(519)));
        RuntimeException e = assertThrows(RuntimeException.class, () -> call("reverseBytes", "00".repeat(521)));
        assertTrue(e.getMessage().contains("520"), e.getMessage());
    }
}

package runar.lang.sdk;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * N-102: the binary {@code /} and {@code %} operators lower to OP_DIV / OP_MOD,
 * which truncate toward zero and ABORT the script on a zero divisor. The
 * interpreter returned 0 for a zero divisor, deriving a post-state the
 * deployed script can never produce.
 *
 * <p>Proves: {@link AnfInterpreter#computeNewState} refuses a zero divisor and
 * truncates toward zero (-7/2 = -3, -7%2 = -1). Does not prove: agreement with
 * an executed script (the expected values are the OP_DIV/OP_MOD semantics, not
 * an execution).
 */
class N102BinaryDivModTest {

    private static Map<String, Object> anf(String op, long a, long b) throws Exception {
        String json = """
            {
              "contractName": "DivProbe",
              "properties": [ { "name": "result", "type": "bigint", "readonly": false } ],
              "methods": [
                {
                  "name": "probe", "params": [], "isPublic": true,
                  "body": [
                    { "name": "a", "value": { "kind": "load_const", "value": %d } },
                    { "name": "b", "value": { "kind": "load_const", "value": %d } },
                    { "name": "r", "value": { "kind": "bin_op", "op": "%s", "left": "a", "right": "b" } },
                    { "name": "u", "value": { "kind": "update_prop", "name": "result", "value": "r" } }
                  ]
                }
              ]
            }
            """.formatted(a, b, op);
        return AnfInterpreter.loadAnf("{\"anf\":" + json + "}");
    }

    private static Object run(String op, long a, long b) throws Exception {
        return AnfInterpreter.computeNewState(
            anf(op, a, b), "probe", Map.of("result", BigInteger.ZERO), Map.of(), List.of()).get("result");
    }

    @Test
    void zeroDivisorIsRefused() throws Exception {
        for (String op : new String[] {"/", "%"}) {
            Map<String, Object> program = anf(op, 7, 0);
            assertThrows(AnfInterpreter.InterpreterException.class, () ->
                AnfInterpreter.computeNewState(
                    program, "probe", Map.of("result", BigInteger.ZERO), Map.of(), List.of()),
                op + " by zero must be refused, the script aborts");
        }
    }

    @Test
    void truncatesTowardZero() throws Exception {
        assertEquals(BigInteger.valueOf(-3), run("/", -7, 2));
        assertEquals(BigInteger.valueOf(-1), run("%", -7, 2));
        assertEquals(BigInteger.valueOf(-3), run("/", 7, -2));
        assertEquals(BigInteger.valueOf(1), run("%", 7, -2));
    }
}

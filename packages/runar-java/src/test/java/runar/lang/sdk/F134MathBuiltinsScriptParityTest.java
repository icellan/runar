package runar.lang.sdk;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Function;

import org.junit.jupiter.api.Test;

import runar.lang.runtime.MockCrypto;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * F-134: the Java mocks of the math builtins ({@link MockCrypto}, what
 * {@code runar.lang.Builtins} delegates to when a contract runs natively) and
 * the SDK {@link AnfInterpreter} (what derives a call's post-state) must
 * compute what the compiled script computes.
 *
 * <p>The expected column was established by EXECUTING the TS compiler's script
 * for each builtin in @bsv/sdk's Spend (fold ON and OFF, identical): OP_DIV /
 * OP_MOD truncate toward zero; a zero divisor aborts; {@code pow} aborts outside
 * {@code 0 <= exp <= 32} (OP_WITHIN guard); {@code sqrt} aborts on {@code n < 0}
 * and {@code n >= 2^495}. {@code null} means the script fails, so the runtime
 * must throw rather than return a number.
 *
 * <p>Proves: for each listed input both Java runtimes return the script's value
 * or throw where the script aborts. Does not prove: agreement outside the
 * table, or anything about the script itself (it is the oracle here).
 */
class F134MathBuiltinsScriptParityTest {

    private static final BigInteger P495 = BigInteger.ONE.shiftLeft(495);

    private record V(String func, BigInteger[] args, BigInteger want) {
        String label() {
            StringBuilder sb = new StringBuilder(func).append('(');
            for (int i = 0; i < args.length; i++) {
                if (i > 0) sb.append(", ");
                sb.append(args[i].equals(P495) ? "2^495" : args[i].toString());
            }
            return sb.append(')').toString();
        }
    }

    private static V v(String func, Long want, long... args) {
        BigInteger[] a = Arrays.stream(args).mapToObj(BigInteger::valueOf).toArray(BigInteger[]::new);
        return new V(func, a, want == null ? null : BigInteger.valueOf(want));
    }

    private static final List<V> VECTORS = List.of(
        v("divmod", -3L, -7, 2),
        v("divmod", -3L, 7, -2),
        v("divmod", null, 1, 0),
        v("mulDiv", -3L, -7, 1, 2),
        v("mulDiv", null, 1, 1, 0),
        v("percentOf", 0L, -1, 5000),
        v("percentOf", -1L, -15000, 1),
        v("pow", null, 2, -1),
        v("pow", 1L, 2, 0),
        v("pow", -8L, -2, 3),
        v("pow", 4294967296L, 2, 32),
        v("pow", null, 2, 33),
        v("pow", null, 1, 40),
        v("sqrt", null, -1),
        v("sqrt", 0L, 0),
        v("sqrt", 2L, 8),
        new V("sqrt", new BigInteger[] {P495}, null),
        v("safediv", -3L, -7, 2),
        v("safediv", null, 1, 0),
        v("safemod", -1L, -7, 2),
        v("safemod", 1L, 7, -2),
        v("safemod", null, 1, 0)
    );

    private static BigInteger nativeCall(String func, BigInteger[] a) {
        return switch (func) {
            case "divmod" -> MockCrypto.divmod(a[0], a[1]);
            case "mulDiv" -> MockCrypto.mulDiv(a[0], a[1], a[2]);
            case "percentOf" -> MockCrypto.percentOf(a[0], a[1]);
            case "pow" -> MockCrypto.pow(a[0], a[1]);
            case "sqrt" -> MockCrypto.sqrt(a[0]);
            case "safediv" -> MockCrypto.safediv(a[0], a[1]);
            case "safemod" -> MockCrypto.safemod(a[0], a[1]);
            default -> throw new IllegalArgumentException(func);
        };
    }

    private static List<String> divergences(Function<V, Object> run) {
        List<String> out = new ArrayList<>();
        for (V c : VECTORS) {
            Object got;
            try {
                got = run.apply(c);
            } catch (RuntimeException e) {
                got = null;
            }
            boolean ok = c.want() == null ? got == null : c.want().equals(got);
            if (!ok) out.add(c.label() + ": script " + c.want() + ", runtime " + got);
        }
        return out;
    }

    @Test
    void mockCryptoMathMatchesScript() {
        List<String> bad = divergences(c -> nativeCall(c.func(), c.args()));
        assertTrue(bad.isEmpty(), "MockCrypto diverges from the script:\n" + String.join("\n", bad));
    }

    @Test
    void anfInterpreterMathMatchesScript() {
        List<String> bad = divergences(c ->
            AnfInterpreter.evalCall(c.func(), new ArrayList<>(Arrays.asList((Object[]) c.args())), null, null));
        assertTrue(bad.isEmpty(), "AnfInterpreter diverges from the script:\n" + String.join("\n", bad));
    }
}

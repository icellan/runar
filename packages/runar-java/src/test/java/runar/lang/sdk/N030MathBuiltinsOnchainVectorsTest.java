package runar.lang.sdk;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Function;

import org.junit.jupiter.api.Test;

import runar.lang.runtime.MockCrypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * N-030 (CL-BUG-104): the Java math builtins ({@link MockCrypto}, what
 * {@code runar.lang.Builtins} delegates to when a contract runs natively) and
 * the SDK {@link AnfInterpreter} (what derives a call's post-state) must return
 * what the COMPILED SCRIPT returns, for every vector in the shared on-chain file
 * {@code packages/runar-zig/src/fixtures/f033-math-builtins-onchain.json}.
 *
 * <p>That file is the oracle: every row is executed on @bsv/sdk Spend.validate
 * by {@code packages/runar-testing/src/__tests__/f033-zig-native-math-onchain.test.ts}
 * (accept at {@code expect}, reject at {@code expect + 1}; an {@code abort} row
 * rejects both {@code == 0} and {@code != 0}). Every other tier replays the
 * same file.
 *
 * <p>Proves: for every {@code cases} and {@code wideCases} row both Java
 * runtimes return the on-chain value, or throw where the script aborts (never a
 * value) — including clamp with lo &gt; hi, log2 of n &lt;= 0 (0, not an error)
 * and saturating at 64, and gcd's partial remainder after 256 Euclid steps.
 * Booleans are compared as script numbers (true == 1, false == 0).
 *
 * <p>Does not prove: inputs outside the file, or the script itself (the oracle).
 */
class N030MathBuiltinsOnchainVectorsTest {

    /** {@code want == null} means the script aborts. */
    private record Row(String fn, BigInteger[] args, BigInteger want) {
        String label() {
            return fn + Arrays.toString(args);
        }
    }

    private static BigInteger big(Object v) {
        if (v instanceof Long l) return BigInteger.valueOf(l);
        if (v instanceof BigInteger b) return b;
        if (v instanceof String s) return new BigInteger(s, 10);
        throw new IllegalArgumentException("not an integer: " + v);
    }

    @SuppressWarnings("unchecked")
    private static List<Row> rows() throws Exception {
        Path p = Paths.get(System.getProperty("user.dir"), "..", "runar-zig", "src", "fixtures",
            "f033-math-builtins-onchain.json");
        Map<String, Object> doc = (Map<String, Object>) Json.parse(Files.readString(p));
        List<Row> out = new ArrayList<>();
        for (String key : List.of("cases", "wideCases")) {
            for (Object o : (List<Object>) doc.get(key)) {
                Map<String, Object> c = (Map<String, Object>) o;
                BigInteger[] args = ((List<Object>) c.get("args")).stream()
                    .map(N030MathBuiltinsOnchainVectorsTest::big).toArray(BigInteger[]::new);
                Object e = c.get("expect");
                BigInteger want;
                if (e instanceof Boolean b) want = b ? BigInteger.ONE : BigInteger.ZERO;
                else if ("abort".equals(e)) want = null;
                else want = big(e);
                out.add(new Row((String) c.get("fn"), args, want));
            }
        }
        return out;
    }

    private static Object nativeCall(String fn, BigInteger[] a) {
        return switch (fn) {
            case "percentOf" -> MockCrypto.percentOf(a[0], a[1]);
            case "mulDiv" -> MockCrypto.mulDiv(a[0], a[1], a[2]);
            case "safediv" -> MockCrypto.safediv(a[0], a[1]);
            case "safemod" -> MockCrypto.safemod(a[0], a[1]);
            case "divmod" -> MockCrypto.divmod(a[0], a[1]);
            case "sqrt" -> MockCrypto.sqrt(a[0]);
            case "log2" -> MockCrypto.log2(a[0]);
            case "pow" -> MockCrypto.pow(a[0], a[1]);
            case "clamp" -> MockCrypto.clamp(a[0], a[1], a[2]);
            case "within" -> MockCrypto.within(a[0], a[1], a[2]);
            case "sign" -> MockCrypto.sign(a[0]);
            case "gcd" -> MockCrypto.gcd(a[0], a[1]);
            case "abs" -> MockCrypto.abs(a[0]);
            case "min" -> MockCrypto.min(a[0], a[1]);
            case "max" -> MockCrypto.max(a[0], a[1]);
            case "bool" -> MockCrypto.bool(a[0]);
            default -> throw new IllegalArgumentException("unmapped builtin " + fn);
        };
    }

    private static BigInteger scriptNumber(Object v) {
        if (v instanceof Boolean b) return b ? BigInteger.ONE : BigInteger.ZERO;
        return (BigInteger) v;
    }

    private static List<String> divergences(List<Row> rows, Function<Row, Object> run) {
        List<String> out = new ArrayList<>();
        for (Row r : rows) {
            BigInteger got;
            try {
                got = scriptNumber(run.apply(r));
            } catch (RuntimeException e) {
                got = null;
            }
            boolean ok = r.want() == null ? got == null : r.want().equals(got);
            if (!ok) out.add(r.label() + ": script " + (r.want() == null ? "abort" : r.want()) + ", runtime " + got);
        }
        return out;
    }

    @Test
    void vectorsCoverEveryMathBuiltin() throws Exception {
        Set<String> fns = new TreeSet<>();
        for (Row r : rows()) fns.add(r.fn());
        assertEquals(new TreeSet<>(List.of("percentOf", "mulDiv", "safediv", "safemod", "divmod", "sqrt",
            "log2", "pow", "clamp", "within", "sign", "gcd", "abs", "min", "max", "bool")), fns);
    }

    @Test
    void mockCryptoMathMatchesOnchainVectors() throws Exception {
        List<Row> rows = rows();
        assertFalse(rows.isEmpty());
        List<String> bad = divergences(rows, r -> nativeCall(r.fn(), r.args()));
        assertTrue(bad.isEmpty(), "MockCrypto diverges from the script:\n" + String.join("\n", bad));
    }

    @Test
    void anfInterpreterMathMatchesOnchainVectors() throws Exception {
        List<Row> rows = rows();
        assertFalse(rows.isEmpty());
        List<String> bad = divergences(rows, r ->
            AnfInterpreter.evalCall(r.fn(), new ArrayList<>(Arrays.asList((Object[]) r.args())), null, null));
        assertTrue(bad.isEmpty(), "AnfInterpreter diverges from the script:\n" + String.join("\n", bad));
    }
}

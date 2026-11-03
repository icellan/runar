package runar.lang.sdk;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import runar.lang.runtime.MockCrypto;
import runar.lang.types.ByteString;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * F-274 (CL-BUG-163): the Java {@link MockCrypto#left}/{@link MockCrypto#right}
 * (what {@code runar.lang.Builtins} delegates to when a contract runs
 * natively) and the SDK {@link AnfInterpreter} (what derives a call's
 * post-state) must return what the COMPILED SCRIPT returns, for every vector
 * in the shared on-chain file
 * {@code packages/runar-zig/src/fixtures/f274-split-builtins-onchain.json}.
 *
 * <p>That file is the oracle: every row is executed on @bsv/sdk
 * Spend.validate by
 * {@code packages/runar-testing/src/__tests__/f274-split-builtins-onchain.test.ts}.
 *
 * <p>Proves: for every row both Java runtimes return the on-chain value, or
 * throw where the script aborts (never a value) — covering n=0, n=len(data),
 * n&gt;len(data), n&lt;0, and an empty {@code data} input.
 * <p>Does not prove: inputs outside the file, or the script itself (the
 * oracle).
 */
class F274SplitBuiltinsOnchainVectorsTest {

    /** {@code want == null} means the script aborts. */
    private record Row(String fn, String data, long n, String want) {
        String label() {
            return fn + "(" + data + ", " + n + ")";
        }
    }

    @SuppressWarnings("unchecked")
    private static List<Row> rows() throws Exception {
        Path p = Paths.get(System.getProperty("user.dir"), "..", "runar-zig", "src", "fixtures",
            "f274-split-builtins-onchain.json");
        Map<String, Object> doc = (Map<String, Object>) Json.parse(Files.readString(p));
        List<Row> out = new ArrayList<>();
        for (Object o : (List<Object>) doc.get("cases")) {
            Map<String, Object> c = (Map<String, Object>) o;
            Object e = c.get("expect");
            String want = "abort".equals(e) ? null : (String) e;
            out.add(new Row((String) c.get("fn"), (String) c.get("data"), ((Number) c.get("n")).longValue(), want));
        }
        return out;
    }

    @Test
    void vectorsCoverBothBuiltins() throws Exception {
        assertEquals(Set.of("left", "right"), rows().stream().map(Row::fn).collect(java.util.stream.Collectors.toSet()));
    }

    @Test
    void mockCryptoSplitMatchesOnchainVectors() throws Exception {
        List<Row> rows = rows();
        assertFalse(rows.isEmpty());
        for (Row r : rows) {
            ByteString data = ByteString.fromHex(r.data());
            BigInteger n = BigInteger.valueOf(r.n());
            if (r.want() == null) {
                assertThrows(RuntimeException.class, () -> callMockCrypto(r.fn(), data, n), r.label());
            } else {
                ByteString got = callMockCrypto(r.fn(), data, n);
                assertEquals(r.want(), got.toHex(), r.label());
            }
        }
    }

    @Test
    void anfInterpreterSplitMatchesOnchainVectors() throws Exception {
        List<Row> rows = rows();
        assertFalse(rows.isEmpty());
        for (Row r : rows) {
            List<Object> args = new ArrayList<>(List.of(r.data(), BigInteger.valueOf(r.n())));
            if (r.want() == null) {
                assertThrows(RuntimeException.class, () -> AnfInterpreter.evalCall(r.fn(), args, null, null), r.label());
            } else {
                Object got = AnfInterpreter.evalCall(r.fn(), args, null, null);
                assertEquals(r.want(), got, r.label());
            }
        }
    }

    private static ByteString callMockCrypto(String fn, ByteString data, BigInteger n) {
        return switch (fn) {
            case "left" -> MockCrypto.left(data, n);
            case "right" -> MockCrypto.right(data, n);
            default -> throw new IllegalArgumentException("unmapped builtin " + fn);
        };
    }
}

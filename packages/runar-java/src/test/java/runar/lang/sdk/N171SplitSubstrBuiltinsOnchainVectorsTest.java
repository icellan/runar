package runar.lang.sdk;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import runar.lang.runtime.MockCrypto;
import runar.lang.types.ByteString;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * N-171 (sibling of F-274): the Java {@link MockCrypto#substr} (what
 * {@code runar.lang.Builtins} delegates to when a contract runs natively)
 * AND the SDK {@link AnfInterpreter} (what derives a call's post-state)
 * must return what the COMPILED SCRIPT returns, for every vector in the
 * shared on-chain file
 * {@code packages/runar-zig/src/fixtures/n171-split-substr-builtins-onchain.json}.
 * The interpreter's {@code split} arm was newly modelled (the same bug
 * shape F-274 fixed for {@code left}/{@code right}: it fell through to the
 * {@code default} arm's {@code null} before this); its {@code substr} arm
 * used to clamp instead of aborting.
 *
 * <p>R67: the interpreter's {@code substr} is now fully abort-faithful. Its
 * one caller via {@code extractScriptCode} ({@code FungibleTokenExample.merge})
 * used to get an empty dummy scriptCode, turning a realistic
 * {@code substr(sc, ...)} call into a POSITIVE overflow the old clamp had
 * to swallow to avoid breaking state derivation. {@code extractScriptCode}
 * now returns the contract's own REAL codePart ({@code RunarContract}'s
 * call path, via {@code AnfInterpreter.WitnessContext}), so {@code substr}
 * can be fully abort-faithful without starving {@code merge} of a realistic
 * scriptCode. {@link AnfInterpreterTest} pins the two literal-negative-input
 * cases that must still abort on their own terms.
 *
 * <p>That file is the oracle: every row is executed on @bsv/sdk
 * Spend.validate by
 * {@code packages/runar-testing/src/__tests__/n171-split-substr-builtins-onchain.test.ts}.
 *
 * <p>Proves: for every {@code substr} row, both {@link MockCrypto#substr}
 * and the SDK {@link AnfInterpreter} return the on-chain value, or throw
 * where the script aborts; for every {@code split} row, the interpreter
 * does the same — covering start/index/length = 0, interior, at the
 * boundary, past the end, negative, and an empty {@code data} input.
 * <p>Does not prove: inputs outside the file, or the script itself (the
 * oracle).
 */
class N171SplitSubstrBuiltinsOnchainVectorsTest {

    /** {@code want == null} means the script aborts. */
    private record Row(String fn, String data, long a, long b, String want) {
        String label() {
            return fn + "(" + data + ", " + a + (fn.equals("substr") ? ", " + b : "") + ")";
        }
    }

    @SuppressWarnings("unchecked")
    private static List<Row> rows() throws Exception {
        Path p = Paths.get(System.getProperty("user.dir"), "..", "runar-zig", "src", "fixtures",
            "n171-split-substr-builtins-onchain.json");
        Map<String, Object> doc = (Map<String, Object>) Json.parse(Files.readString(p));
        List<Row> out = new ArrayList<>();
        for (Object o : (List<Object>) doc.get("cases")) {
            Map<String, Object> c = (Map<String, Object>) o;
            Object e = c.get("expect");
            String want = "abort".equals(e) ? null : (String) e;
            out.add(new Row((String) c.get("fn"), (String) c.get("data"),
                ((Number) c.get("a")).longValue(), ((Number) c.get("b")).longValue(), want));
        }
        return out;
    }

    @Test
    void mockCryptoSubstrMatchesOnchainVectors() throws Exception {
        List<Row> rows = rows().stream().filter(r -> r.fn().equals("substr")).toList();
        assertFalse(rows.isEmpty());
        for (Row r : rows) {
            ByteString data = ByteString.fromHex(r.data());
            BigInteger start = BigInteger.valueOf(r.a());
            BigInteger length = BigInteger.valueOf(r.b());
            if (r.want() == null) {
                assertThrows(RuntimeException.class, () -> MockCrypto.substr(data, start, length), r.label());
            } else {
                ByteString got = MockCrypto.substr(data, start, length);
                assertEquals(r.want(), got.toHex(), r.label());
            }
        }
    }

    @Test
    void anfInterpreterSplitSubstrMatchesOnchainVectors() throws Exception {
        List<Row> rows = rows();
        assertFalse(rows.isEmpty());
        for (Row r : rows) {
            List<Object> args = r.fn().equals("substr")
                ? new ArrayList<>(List.of(r.data(), BigInteger.valueOf(r.a()), BigInteger.valueOf(r.b())))
                : new ArrayList<>(List.of(r.data(), BigInteger.valueOf(r.a())));
            if (r.want() == null) {
                assertThrows(RuntimeException.class, () -> AnfInterpreter.evalCall(r.fn(), args, null, null), r.label());
            } else {
                Object got = AnfInterpreter.evalCall(r.fn(), args, null, null);
                assertEquals(r.want(), got, r.label());
            }
        }
    }
}

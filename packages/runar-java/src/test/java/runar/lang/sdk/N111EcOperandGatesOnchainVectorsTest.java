package runar.lang.sdk;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import runar.lang.runtime.MockCrypto;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * N-111: the Java native EC builtins ({@link MockCrypto}, what
 * {@code runar.lang.Builtins} delegates to when a contract runs natively)
 * must apply the compiled script's operand gates -- ecAdd / ecNegate: 64
 * bytes and x, y &lt; p (R-117); ecMul: on-curve or the all-zero identity O
 * (R-157); ecPointX / ecPointY / ecEncodeCompressed: width only -- and its
 * addition law (inv(0) = 0, so an (x, 0) doubling is a value).
 *
 * <p>Oracle: {@code packages/runar-zig/src/fixtures/n111-ec-operand-gates-onchain.json},
 * every row executed on @bsv/sdk Spend.validate by
 * {@code packages/runar-testing/src/__tests__/n111-ec-operand-gates-onchain.test.ts}.
 * A Point operand is built with {@link MockCrypto.Point#fromRaw64}, the
 * only bytes-to-Point path, so the width rows exercise its length check.
 *
 * <p>Proves: for every row, each builtin returns the on-chain value, or
 * throws where the script aborts (never a value).
 * <p>Does not prove: inputs outside the file, or the script itself.
 */
class N111EcOperandGatesOnchainVectorsTest {

    private static final HexFormat HEX = HexFormat.of();

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> rows() throws Exception {
        Path p = Paths.get(System.getProperty("user.dir"), "..", "runar-zig", "src", "fixtures",
            "n111-ec-operand-gates-onchain.json");
        Map<String, Object> doc = (Map<String, Object>) Json.parse(Files.readString(p));
        List<Map<String, Object>> out = new ArrayList<>();
        for (Object o : (List<Object>) doc.get("cases")) out.add((Map<String, Object>) o);
        return out;
    }

    private static MockCrypto.Point pt(Object hex) {
        return MockCrypto.Point.fromRaw64(HEX.parseHex((String) hex));
    }

    private static String run(Map<String, Object> r) {
        BigInteger k = r.containsKey("k") ? new BigInteger((String) r.get("k")) : null;
        return switch ((String) r.get("fn")) {
            case "ecAdd" -> MockCrypto.ecAdd(pt(r.get("p")), pt(r.get("q"))).toHex();
            case "ecMul" -> MockCrypto.ecMul(pt(r.get("p")), k).toHex();
            case "ecMulGen" -> MockCrypto.ecMulGen(k).toHex();
            case "ecNegate" -> MockCrypto.ecNegate(pt(r.get("p"))).toHex();
            case "ecPointX" -> MockCrypto.ecPointX(pt(r.get("p"))).toString();
            case "ecPointY" -> MockCrypto.ecPointY(pt(r.get("p"))).toString();
            case "ecEncodeCompressed" -> HEX.formatHex(MockCrypto.ecEncodeCompressed(pt(r.get("p"))).toByteArray());
            default -> throw new AssertionError("unknown fn " + r.get("fn"));
        };
    }

    @Test
    void everyEcBuiltinMatchesTheOnchainOperandGates() throws Exception {
        List<Map<String, Object>> rows = rows();
        assertFalse(rows.isEmpty());
        List<String> failures = new ArrayList<>();
        for (int i = 0; i < rows.size(); i++) {
            Map<String, Object> r = rows.get(i);
            String want = (String) r.get("expect");
            String got;
            try {
                got = run(r);
            } catch (RuntimeException e) {
                got = null;
                if (!"abort".equals(want)) {
                    failures.add("row " + i + " " + r.get("fn") + " [" + r.get("why") + "]: want " + want + ", threw " + e);
                }
                continue;
            }
            if (!want.equals(got)) {
                failures.add("row " + i + " " + r.get("fn") + " [" + r.get("why") + "]: want " + want + ", got " + got);
            }
        }
        assertTrue(failures.isEmpty(), failures.size() + " rows diverge:\n" + String.join("\n", failures));
    }
}

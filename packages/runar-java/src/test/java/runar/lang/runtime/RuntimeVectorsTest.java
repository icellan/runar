package runar.lang.runtime;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import runar.lang.sdk.Json;
import runar.lang.types.ByteString;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;

/**
 * Cross-SDK runtime conformance for hash primitives. Loads
 * {@code conformance/runtime-vectors/hashes.json} — the shared canonical
 * vector set — and asserts Java's {@link MockCrypto} matches every entry.
 *
 * <p>The same JSON file is the single source of truth for all 7 SDKs.
 * Any change here must be mirrored in every consumer test (listed in
 * the JSON's {@code _consumers} field). Inline divergence is a
 * cross-SDK conformance regression and must be fixed.
 */
class RuntimeVectorsTest {

    private static final HexFormat HEX = HexFormat.of();
    private static final Path VECTORS = locateVectors();

    @TestFactory
    Iterable<DynamicTest> sha256FinalizeMatchesEveryVector() throws Exception {
        Map<String, Object> root = loadVectors();
        @SuppressWarnings("unchecked")
        List<Object> cases = (List<Object>) root.get("sha256_finalize");
        return cases.stream().map(c -> {
            @SuppressWarnings("unchecked")
            Map<String, Object> v = (Map<String, Object>) c;
            String name = (String) v.get("name");
            return dynamicTest("sha256_finalize[" + name + "]", () -> {
                ByteString state = ByteString.fromHex((String) v.get("state"));
                ByteString remaining = ByteString.fromHex((String) v.get("remaining"));
                BigInteger bitLen = BigInteger.valueOf(((Number) v.get("msg_bit_len")).longValue());
                ByteString got = MockCrypto.sha256Finalize(state, remaining, bitLen);
                assertEquals((String) v.get("expected"), got.toHex(),
                    "sha256_finalize[" + name + "]: Java runtime diverges from canonical vector");
            });
        }).toList();
    }

    @TestFactory
    Iterable<DynamicTest> blake3HashMatchesEveryVector() throws Exception {
        Map<String, Object> root = loadVectors();
        @SuppressWarnings("unchecked")
        List<Object> cases = (List<Object>) root.get("blake3_hash");
        return cases.stream().map(c -> {
            @SuppressWarnings("unchecked")
            Map<String, Object> v = (Map<String, Object>) c;
            String name = (String) v.get("name");
            return dynamicTest("blake3_hash[" + name + "]", () -> {
                ByteString input = ByteString.fromHex((String) v.get("input"));
                ByteString got = MockCrypto.blake3Hash(input);
                assertEquals((String) v.get("expected"), got.toHex(),
                    "blake3_hash[" + name + "]: Java runtime diverges from canonical vector");
            });
        }).toList();
    }

    @TestFactory
    Iterable<DynamicTest> blake3CompressMatchesEveryVector() throws Exception {
        Map<String, Object> root = loadVectors();
        @SuppressWarnings("unchecked")
        List<Object> cases = (List<Object>) root.get("blake3_compress");
        return cases.stream().map(c -> {
            @SuppressWarnings("unchecked")
            Map<String, Object> v = (Map<String, Object>) c;
            String name = (String) v.get("name");
            return dynamicTest("blake3_compress[" + name + "]", () -> {
                ByteString state = ByteString.fromHex((String) v.get("state"));
                ByteString block = ByteString.fromHex((String) v.get("block"));
                ByteString got = MockCrypto.blake3Compress(state, block);
                assertEquals((String) v.get("expected"), got.toHex(),
                    "blake3_compress[" + name + "]: Java runtime diverges from canonical vector");
            });
        }).toList();
    }

    /* ------------------------------------------------------------------ */

    @SuppressWarnings("unchecked")
    private static Map<String, Object> loadVectors() throws Exception {
        return (Map<String, Object>) Json.parse(Files.readString(VECTORS));
    }

    private static Path locateVectors() {
        // The Java SDK tests run from packages/runar-java/. The shared
        // vectors live at conformance/runtime-vectors/hashes.json relative
        // to the repo root.
        Path candidate = Path.of("../../conformance/runtime-vectors/hashes.json")
            .toAbsolutePath().normalize();
        if (Files.exists(candidate)) return candidate;
        // Fallback for runs from the repo root.
        candidate = Path.of("conformance/runtime-vectors/hashes.json")
            .toAbsolutePath().normalize();
        if (Files.exists(candidate)) return candidate;
        throw new IllegalStateException(
            "RuntimeVectorsTest: cannot locate conformance/runtime-vectors/hashes.json"
        );
    }
}

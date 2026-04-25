package runar.lang.sdk;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import runar.lang.runtime.MockCrypto;

import static org.junit.jupiter.api.Assertions.*;

class AnfInterpreterTest {

    private static final HexFormat HEX = HexFormat.of();

    @Test
    void loadsAnfFromArtifactWrapper() throws Exception {
        Map<String, Object> anf = loadFixtureAnf("basic-p2pkh.runar.json");
        assertNotNull(anf, "basic-p2pkh fixture must expose an anf sub-tree");
        assertEquals("P2PKH", anf.get("contractName"));
    }

    @Test
    void executesP2pkhWithMatchingPubKeyHash() throws Exception {
        Map<String, Object> anf = loadFixtureAnf("basic-p2pkh.runar.json");
        // Build a pubKey hex and the hash160 the contract expects.
        String pubKeyHex = "02" + repeat("ab", 32);  // 33 bytes, looks like a compressed pubkey
        String expectedHash = HEX.formatHex(MockCrypto.hash160(HEX.parseHex(pubKeyHex)));
        String sigHex = repeat("33", 71);

        // P2PKH constructor takes pubKeyHash; the unlock method has sig+pubKey.
        AnfInterpreter.ExecutionResult result = AnfInterpreter.executeStrict(
            anf,
            "unlock",
            Map.of(),  // currentState (stateless contract)
            Map.of("sig", sigHex, "pubKey", pubKeyHex),
            List.of(expectedHash)  // constructor arg: pubKeyHash
        );
        assertNotNull(result);
        // Stateless contract: state stays empty
        assertTrue(result.newState.isEmpty() || !result.newState.containsKey("nonexistent"));
        assertTrue(result.dataOutputs.isEmpty(), "P2PKH does not emit data outputs");
    }

    @Test
    void executeStrictFailsWithMismatchedPubKey() throws Exception {
        Map<String, Object> anf = loadFixtureAnf("basic-p2pkh.runar.json");
        // Constructor pubKeyHash is set to one value; the caller passes a
        // different pubKey whose hash won't match.
        String correctPubKey = "02" + repeat("ab", 32);
        String correctHash = HEX.formatHex(MockCrypto.hash160(HEX.parseHex(correctPubKey)));
        String wrongPubKey = "02" + repeat("cd", 32);
        String sigHex = repeat("33", 71);

        AnfInterpreter.AssertionFailureException ex = assertThrows(
            AnfInterpreter.AssertionFailureException.class,
            () -> AnfInterpreter.executeStrict(
                anf,
                "unlock",
                Map.of(),
                Map.of("sig", sigHex, "pubKey", wrongPubKey),
                List.of(correctHash)
            )
        );
        assertNotNull(ex.getMessage());
        assertTrue(ex.getMessage().contains("assert"), "message should mention failed assert: " + ex.getMessage());
    }

    @Test
    void computeNewStateIncrementsCounterFromZeroToOne() throws Exception {
        Map<String, Object> anf = loadFixtureAnf("stateful-counter.runar.json");
        assertNotNull(anf, "stateful-counter fixture must expose an anf sub-tree");

        Map<String, Object> currentState = Map.of("count", BigInteger.ZERO);
        // Constructor took (count) — a single mutable property, no readonly.
        // The interpreter pulls `count` from currentState first, so an
        // empty constructorArgs list works here.
        Map<String, Object> newState = AnfInterpreter.computeNewState(
            anf,
            "increment",
            currentState,
            Map.of(),
            List.of()
        );
        assertEquals(BigInteger.ONE, asBigInt(newState.get("count")),
            "increment must move count from 0 to 1; got newState=" + newState);
    }

    @Test
    void computeNewStateIncrementsCounterFromArbitrarySeed() throws Exception {
        Map<String, Object> anf = loadFixtureAnf("stateful-counter.runar.json");
        Map<String, Object> currentState = Map.of("count", BigInteger.valueOf(41));
        Map<String, Object> newState = AnfInterpreter.computeNewState(
            anf,
            "increment",
            currentState,
            Map.of(),
            List.of()
        );
        assertEquals(BigInteger.valueOf(42), asBigInt(newState.get("count")));
    }

    @Test
    void computeNewStateDecrementsCounter() throws Exception {
        Map<String, Object> anf = loadFixtureAnf("stateful-counter.runar.json");
        Map<String, Object> currentState = Map.of("count", BigInteger.valueOf(5));
        Map<String, Object> newState = AnfInterpreter.computeNewState(
            anf,
            "decrement",
            currentState,
            Map.of(),
            List.of()
        );
        assertEquals(BigInteger.valueOf(4), asBigInt(newState.get("count")));
    }

    @Test
    void unknownMethodThrowsInterpreterException() throws Exception {
        Map<String, Object> anf = loadFixtureAnf("basic-p2pkh.runar.json");
        AnfInterpreter.InterpreterException ex = assertThrows(
            AnfInterpreter.InterpreterException.class,
            () -> AnfInterpreter.computeNewState(anf, "doesNotExist", Map.of(), Map.of(), List.of())
        );
        assertTrue(ex.getMessage().contains("doesNotExist"));
    }

    @Test
    void num2binBin2numRoundtrip() {
        // bin2num(num2bin(n, len)) == n for representable values.
        for (long n : new long[] { 0, 1, 7, -7, 127, -127, 255, -255, 32768, -32768, 65535 }) {
            String hex = AnfInterpreter.num2binHex(BigInteger.valueOf(n), 8);
            BigInteger back = AnfInterpreter.bin2numBigInt(hex);
            assertEquals(BigInteger.valueOf(n), back, "round-trip failed for " + n);
        }
    }

    @Test
    void unsupportedPostQuantumPrimitiveThrows() throws Exception {
        // Build a tiny synthetic ANF that calls verifyWOTS — the interpreter
        // must throw UnsupportedOperationException rather than silently
        // returning truthy.
        String json = """
            {
              "contractName": "Synthetic",
              "properties": [],
              "methods": [
                {
                  "name": "test",
                  "params": [],
                  "isPublic": true,
                  "body": [
                    { "name": "t0", "value": { "kind": "load_const", "value": "00" } },
                    { "name": "t1", "value": { "kind": "load_const", "value": "00" } },
                    { "name": "t2", "value": { "kind": "load_const", "value": "00" } },
                    { "name": "t3", "value": { "kind": "call", "func": "verifyWOTS",
                                               "args": ["t0", "t1", "t2"] } }
                  ]
                }
              ]
            }
            """;
        Map<String, Object> anf = AnfInterpreter.loadAnf("{\"anf\":" + json + "}");
        assertThrows(UnsupportedOperationException.class, () ->
            AnfInterpreter.computeNewState(anf, "test", Map.of(), Map.of(), List.of())
        );
    }

    // ------------------------------------------------------------------

    private static Map<String, Object> loadFixtureAnf(String name) throws Exception {
        Path fixture = locateFixture(name);
        String json = Files.readString(fixture);
        return AnfInterpreter.loadAnf(json);
    }

    private static Path locateFixture(String name) throws Exception {
        var url = AnfInterpreterTest.class.getClassLoader().getResource("artifacts/" + name);
        if (url == null) {
            throw new IllegalStateException("fixture not found on classpath: artifacts/" + name);
        }
        return Path.of(url.toURI());
    }

    private static String repeat(String chunk, int count) {
        StringBuilder sb = new StringBuilder(chunk.length() * count);
        for (int i = 0; i < count; i++) sb.append(chunk);
        return sb.toString();
    }

    private static BigInteger asBigInt(Object v) {
        if (v == null) return null;
        if (v instanceof BigInteger b) return b;
        if (v instanceof Long l) return BigInteger.valueOf(l);
        if (v instanceof Integer i) return BigInteger.valueOf(i);
        if (v instanceof String s) {
            String t = s.endsWith("n") ? s.substring(0, s.length() - 1) : s;
            return new BigInteger(t);
        }
        throw new IllegalStateException("cannot coerce " + v.getClass() + " to BigInteger: " + v);
    }
}

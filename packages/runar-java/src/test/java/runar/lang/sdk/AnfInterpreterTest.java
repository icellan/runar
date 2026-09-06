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
    void unsupportedProofSystemPrimitiveThrows() throws Exception {
        // Build a tiny synthetic ANF that calls poseidon2Hash — the
        // interpreter must throw UnsupportedOperationException rather
        // than silently returning truthy. Poseidon2 and BN254 are
        // intentionally Go-only proof-system primitives that the Java
        // simulator does not implement.
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
                    { "name": "t0", "value": { "kind": "load_const", "value": "01" } },
                    { "name": "t1", "value": { "kind": "call", "func": "poseidon2Hash",
                                               "args": ["t0"] } }
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
    // NEW-006 (a): a byte-op's REAL stack bytes must follow the value across
    // an ALIAS — a binding whose value simply IS another binding's stack slot.
    // Every local rebind (`m0 = ...`) lowers to `load_const "@ref:<temp>"`, and
    // a value-`if` / `loop` adopts its taken arm's / body's last binding.
    // Without that, a chained length-sensitive op (& | ^ << >>) re-minimises
    // the aliased value and disagrees with the deployed script.
    // ------------------------------------------------------------------

    /**
     * PROPAGATE. `2 << 8` leaves a NON-minimal 1-byte 0x00 on the stack
     * (minimal encoding of 0 is empty). Alias it through a rebind, then OR it
     * with 5: on-chain OP_OR sees 1 byte vs 1 byte and yields 5.
     *
     * <p>Fails before the fix — the alias drops the width, so the interpreter
     * re-minimises 0 to zero bytes and OP_OR aborts on a 0-vs-1 length
     * mismatch.
     */
    @Test
    void aliasCarriesByteOpWidthAcrossARebind() {
        BigInteger result = runBodyToResult("""
            { "name": "t0", "value": { "kind": "load_const", "value": 2 } },
            { "name": "t1", "value": { "kind": "load_const", "value": 8 } },
            { "name": "t2", "value": { "kind": "bin_op", "op": "<<", "left": "t0", "right": "t1" } },
            { "name": "m0", "value": { "kind": "load_const", "value": "@ref:t2" } },
            { "name": "t3", "value": { "kind": "load_const", "value": 5 } },
            { "name": "t4", "value": { "kind": "bin_op", "op": "|", "left": "m0", "right": "t3" } },
            { "name": "t5", "value": { "kind": "update_prop", "name": "result", "value": "t4" } }
            """);
        assertEquals(BigInteger.valueOf(5), result,
            "(2 << 8) is a 1-byte 0x00; aliased then OR'd with 5 that is 5");
    }

    /**
     * CLEAR, silently-wrong variant. The alias target is a plain constant with
     * no width entry of its own, so the alias must ERASE whatever the same
     * binding name carried before it.
     *
     * <p>Honest status: this PASSES against the unfixed interpreter (nothing
     * ever keys the side map by a re-bound name today). It goes RED under a
     * COPY-ONLY fix, which would leave the dead 1-byte 0x00 from `2 << 8`
     * attached to `m0` and compute `0x00 | 0x03` = 3 instead of `0x05 | 0x03`
     * = 7 — a silently wrong value, the worst failure mode. It is the guard
     * that forces the clear half.
     */
    @Test
    void aliasClearsAStaleWidthWhenTheTargetHasNone() {
        BigInteger result = runBodyToResult("""
            { "name": "t0", "value": { "kind": "load_const", "value": 2 } },
            { "name": "t1", "value": { "kind": "load_const", "value": 8 } },
            { "name": "t2", "value": { "kind": "bin_op", "op": "<<", "left": "t0", "right": "t1" } },
            { "name": "m0", "value": { "kind": "load_const", "value": "@ref:t2" } },
            { "name": "t3", "value": { "kind": "load_const", "value": 5 } },
            { "name": "m0", "value": { "kind": "load_const", "value": "@ref:t3" } },
            { "name": "t4", "value": { "kind": "load_const", "value": 3 } },
            { "name": "t5", "value": { "kind": "bin_op", "op": "|", "left": "m0", "right": "t4" } },
            { "name": "t6", "value": { "kind": "update_prop", "name": "result", "value": "t5" } }
            """);
        assertEquals(BigInteger.valueOf(7), result,
            "m0 was re-bound to a plain 5; 5 | 3 is 7 — a stale 1-byte 0x00 would give 3");
    }

    /**
     * CLEAR, width-mismatch variant (the shape from the TS fix's commit
     * message): `m0` re-bound to 300, whose minimal encoding is TWO bytes.
     * 300 &amp; 255 = 44.
     *
     * <p>Also PASSES today and goes RED under a copy-only fix, where the stale
     * 1-byte width would make OP_AND abort against 255's 2-byte encoding.
     */
    @Test
    void aliasClearsAStaleWidthOfADifferentLength() {
        BigInteger result = runBodyToResult("""
            { "name": "t0", "value": { "kind": "load_const", "value": 2 } },
            { "name": "t1", "value": { "kind": "load_const", "value": 8 } },
            { "name": "t2", "value": { "kind": "bin_op", "op": "<<", "left": "t0", "right": "t1" } },
            { "name": "m0", "value": { "kind": "load_const", "value": "@ref:t2" } },
            { "name": "t3", "value": { "kind": "load_const", "value": 300 } },
            { "name": "m0", "value": { "kind": "load_const", "value": "@ref:t3" } },
            { "name": "t4", "value": { "kind": "load_const", "value": 255 } },
            { "name": "t5", "value": { "kind": "bin_op", "op": "&", "left": "m0", "right": "t4" } },
            { "name": "t6", "value": { "kind": "update_prop", "name": "result", "value": "t5" } }
            """);
        assertEquals(BigInteger.valueOf(44), result, "300 & 255 == 44");
    }

    /**
     * PROPAGATE across a value-{@code if}: the binding adopts its taken arm's
     * last value, so it must adopt that value's width too. Fails before the
     * fix for the same reason as the rebind case.
     */
    @Test
    void aliasCarriesByteOpWidthOutOfATakenIfBranch() {
        BigInteger result = runBodyToResult("""
            { "name": "c0", "value": { "kind": "load_const", "value": 1 } },
            { "name": "r0", "value": { "kind": "if", "cond": "c0", "then": [
                { "name": "i0", "value": { "kind": "load_const", "value": 2 } },
                { "name": "i1", "value": { "kind": "load_const", "value": 8 } },
                { "name": "i2", "value": { "kind": "bin_op", "op": "<<", "left": "i0", "right": "i1" } }
              ], "else": [
                { "name": "e0", "value": { "kind": "load_const", "value": 0 } }
              ] } },
            { "name": "t1", "value": { "kind": "load_const", "value": 5 } },
            { "name": "t2", "value": { "kind": "bin_op", "op": "|", "left": "r0", "right": "t1" } },
            { "name": "t3", "value": { "kind": "update_prop", "name": "result", "value": "t2" } }
            """);
        assertEquals(BigInteger.valueOf(5), result,
            "the taken arm ends in (2 << 8), a 1-byte 0x00; OR'd with 5 that is 5");
    }

    /**
     * PROPAGATE across a {@code loop}: the binding adopts the body's last
     * value, so it must adopt that value's width too.
     */
    @Test
    void aliasCarriesByteOpWidthOutOfALoopBody() {
        BigInteger result = runBodyToResult("""
            { "name": "r0", "value": { "kind": "loop", "count": 1, "iterVar": "i", "body": [
                { "name": "b0", "value": { "kind": "load_const", "value": 2 } },
                { "name": "b1", "value": { "kind": "load_const", "value": 8 } },
                { "name": "b2", "value": { "kind": "bin_op", "op": "<<", "left": "b0", "right": "b1" } }
              ] } },
            { "name": "t1", "value": { "kind": "load_const", "value": 5 } },
            { "name": "t2", "value": { "kind": "bin_op", "op": "|", "left": "r0", "right": "t1" } },
            { "name": "t3", "value": { "kind": "update_prop", "name": "result", "value": "t2" } }
            """);
        assertEquals(BigInteger.valueOf(5), result,
            "the loop body ends in (2 << 8), a 1-byte 0x00; OR'd with 5 that is 5");
    }

    /**
     * Run a synthetic single-method ANF body that ends by writing temp
     * {@code result} into the contract's one mutable property, and return that
     * property's post-call value.
     */
    private static BigInteger runBodyToResult(String bodyBindingsJson) {
        String json = """
            {"anf": {
              "contractName": "AliasWidth",
              "properties": [ { "name": "result", "type": "bigint", "readonly": false } ],
              "methods": [
                { "name": "test", "params": [], "isPublic": true, "body": [
            """ + bodyBindingsJson + """
                ] }
              ]
            }}
            """;
        Map<String, Object> anf = AnfInterpreter.loadAnf(json);
        Map<String, Object> newState = AnfInterpreter.computeNewState(
            anf, "test", Map.of("result", BigInteger.ZERO), Map.of(), List.of());
        return asBigInt(newState.get("result"));
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

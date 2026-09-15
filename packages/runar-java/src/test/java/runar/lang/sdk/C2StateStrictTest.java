package runar.lang.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import runar.lang.sdk.RunarArtifact.ABI;
import runar.lang.sdk.RunarArtifact.ABIConstructor;
import runar.lang.sdk.RunarArtifact.FixedArrayMeta;
import runar.lang.sdk.RunarArtifact.StateField;

/**
 * C2 — {@code StateSerializer.deserialize} failed OPEN.
 *
 * <p>The state blob is read back out of a deployed locking script's OP_RETURN
 * tail ({@code RunarContract.fromUtxo} -&gt; {@code extractFromScript} -&gt;
 * {@code deserialize}). That script is something any third party can construct,
 * so the blob is untrusted input — and the caller then builds and SIGNS a
 * continuation output committing to whatever state came back.
 *
 * <p>Every arm of the Java decoder was a bare {@code hex.substring(offset,
 * offset + N)} that threw {@link StringIndexOutOfBoundsException} — a raw JDK
 * bounds error, not a typed refusal — and {@code deserialize} had no
 * trailing-byte check at all. Measured before the fix, gradle test exit 0,
 * {@code tests=1 failures=0 errors=0}:
 *
 * <pre>
 * 2a00000000000000        a,b bigint    -&gt; StringIndexOutOfBoundsException: begin 16, end 32, length 16
 * 2a.. + 01.. + deadbeef  a,b bigint    -&gt; {a=42, b=1}          (trailing bytes dropped)
 * 4b aaaaaa               m ByteString  -&gt; StringIndexOutOfBoundsException: begin 2, end 152, length 8
 * aa x10                  k PubKey      -&gt; StringIndexOutOfBoundsException: begin 0, end 66, length 20
 * 55                      m ByteString  -&gt; {m=}                 (non-push opcode consumed silently)
 * </pre>
 *
 * <p>The semantics here are TypeScript's (C28,
 * {@code packages/runar-sdk/src/state.ts}, test {@code c28-state-strict.test.ts}):
 * refuse rather than default, and refuse trailing bytes. All seven SDKs read
 * the SAME wire format, so the triggering conditions must be identical even
 * though each tier throws its own exception type.
 */
class C2StateStrictTest {

    private static StateField f(String name, String type, int index) {
        return new StateField(name, type, index, null, null);
    }

    private static final List<StateField> TWO_INTS = List.of(f("a", "bigint", 0), f("b", "bigint", 1));
    private static final List<StateField> BYTESTR = List.of(f("blob", "ByteString", 0));
    private static final List<StateField> PUBKEY = List.of(f("k", "PubKey", 0));

    private static String rep(String unit, int n) {
        return unit.repeat(n);
    }

    private static RunarArtifact artifactWith(List<StateField> fields) {
        return new RunarArtifact(
            "v0", "0", "C2",
            new ABI(new ABIConstructor(List.of()), List.of()),
            "51", "OP_1", null,
            fields, List.of(), List.of(), null, null);
    }

    // -----------------------------------------------------------------------
    // The five hostile blobs from the finding, verbatim.
    // -----------------------------------------------------------------------

    @Test
    void truncatedTrailingBigintIsRefused() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> StateSerializer.deserialize(TWO_INTS, "2a00000000000000"));
        assertTrue(e.getMessage().toLowerCase().contains("truncat"), e.getMessage());
    }

    @Test
    void trailingBytesAreRefused() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> StateSerializer.deserialize(TWO_INTS, "2a000000000000000100000000000000deadbeef"));
        assertTrue(e.getMessage().toLowerCase().contains("trailing"), e.getMessage());
    }

    @Test
    void pushPayloadRunningPastTheEndIsRefused() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> StateSerializer.deserialize(BYTESTR, "4baaaaaa"));
        assertTrue(e.getMessage().toLowerCase().contains("truncat"), e.getMessage());
    }

    @Test
    void shortPubKeyIsRefused() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> StateSerializer.deserialize(PUBKEY, rep("aa", 10)));
        assertTrue(e.getMessage().toLowerCase().contains("truncat"), e.getMessage());
    }

    @Test
    void nonPushOpcodeIsRefused() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> StateSerializer.deserialize(BYTESTR, "55"));
        assertTrue(e.getMessage().contains("is not a push opcode"), e.getMessage());
    }

    // -----------------------------------------------------------------------
    // Truncation, exhaustively.
    //
    // A StringIndexOutOfBoundsException is a DIFFERENT failure mode from a
    // wrong value: it is a raw JDK bounds error escaping the SDK on
    // attacker-controlled input. assertThrows(IllegalArgumentException) fails
    // on it, so this also pins that every arm became a typed refusal.
    // -----------------------------------------------------------------------

    @ParameterizedTest
    @CsvSource({
        "boolean,1", "bool,1", "bigint,8", "int,8", "PubKey,33", "Addr,20",
        "Ripemd160,20", "Sha256,32", "Point,64", "P256Point,64", "P384Point,96",
    })
    void everyFixedWidthArmRefusesAShortBlob(String type, int width) {
        assertThrows(IllegalArgumentException.class,
            () -> StateSerializer.deserialize(List.of(f("v", type, 0)), rep("aa", width - 1)));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "4c",         // OP_PUSHDATA1, no length byte
        "4c05aabb",   // declares 5 bytes, 2 supplied
        "4d",         // OP_PUSHDATA2, no length bytes
        "4d00",       // half a length
        "4d0500aabb", // declares 5, 2 supplied
        "4e",         // OP_PUSHDATA4, no length bytes
        "4e05000000", // declares 5, none supplied
        "05aabb",     // direct push declares 5, 2 supplied
    })
    void pushFramingIsBoundsChecked(String blob) {
        assertThrows(IllegalArgumentException.class,
            () -> StateSerializer.deserialize(BYTESTR, blob));
    }

    @Test
    void missingPushOpcodeByteEntirelyIsRefused() {
        List<StateField> fields = List.of(f("n", "bigint", 0), f("blob", "ByteString", 1));
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> StateSerializer.deserialize(fields, "0100000000000000"));
        assertTrue(e.getMessage().toLowerCase().contains("truncat"), e.getMessage());
    }

    @Test
    void truncatedFixedArrayElementIsRefused() {
        List<StateField> fields = List.of(new StateField(
            "board", "FixedArray<bigint, 3>", 0, null,
            new FixedArrayMeta("bigint", 3, List.of("board__0", "board__1", "board__2"))));
        String full = StateSerializer.serialize(fields, Map.of("board", List.of(1L, 2L, 3L)));
        assertEquals(48, full.length());
        assertThrows(IllegalArgumentException.class,
            () -> StateSerializer.deserialize(fields, full.substring(0, 40)));
    }

    @Test
    void oddLengthBlobIsRefused() {
        assertThrows(IllegalArgumentException.class,
            () -> StateSerializer.deserialize(List.of(f("count", "bigint", 0)), "00112233445566778"));
    }

    // -----------------------------------------------------------------------
    // Overlong tails
    // -----------------------------------------------------------------------

    @Test
    void oneUnexpectedTrailingByteIsRefused() {
        List<StateField> one = List.of(f("a", "bigint", 0));
        String full = StateSerializer.serialize(one, Map.of("a", 42L));
        assertThrows(IllegalArgumentException.class,
            () -> StateSerializer.deserialize(one, full + "ff"));
    }

    @Test
    void trailingByteAfterAVariableLengthFieldIsRefused() {
        String full = StateSerializer.serialize(BYTESTR, Map.of("blob", "aabbcc"));
        assertThrows(IllegalArgumentException.class,
            () -> StateSerializer.deserialize(BYTESTR, full + "00"));
    }

    @Test
    void aWholeExtraFieldIsRefused() {
        String full = StateSerializer.serialize(TWO_INTS, Map.of("a", 1L, "b", 2L));
        assertThrows(IllegalArgumentException.class,
            () -> StateSerializer.deserialize(List.of(f("a", "bigint", 0)), full));
    }

    @Test
    void extractFromScriptSurfacesACorruptedContinuation() {
        List<StateField> fields = List.of(f("count", "bigint", 0));
        RunarArtifact artifact = artifactWith(fields);
        String stateHex = StateSerializer.serialize(fields, Map.of("count", 5L));
        assertThrows(IllegalArgumentException.class,
            () -> StateSerializer.extractFromScript(artifact, "51" + "6a" + stateHex + "ff"));
    }

    // -----------------------------------------------------------------------
    // CONTROLS — a guard that rejects legitimate state is just as broken.
    // -----------------------------------------------------------------------

    @Test
    void controlWellFormedStateStillRoundTrips() {
        List<StateField> fields = List.of(
            f("count", "bigint", 0),
            f("active", "boolean", 1),
            f("owner", "PubKey", 2),
            f("blob", "ByteString", 3));
        String owner = rep("cd", 33);
        Map<String, Object> values = new HashMap<>();
        values.put("count", -9L);
        values.put("active", true);
        values.put("owner", owner);
        values.put("blob", "deadbeef");

        Map<String, Object> got = StateSerializer.deserialize(fields, StateSerializer.serialize(fields, values));
        assertEquals(BigInteger.valueOf(-9), got.get("count"));
        assertEquals(true, got.get("active"));
        assertEquals(owner, got.get("owner"));
        assertEquals("deadbeef", got.get("blob"));
    }

    @Test
    void controlOneByteByteStringInTheOpNValueRange() {
        String hex = StateSerializer.serialize(BYTESTR, Map.of("blob", "05"));
        // <len><data>, the compiler's on-chain state codec — NOT the MINIMALDATA
        // opcode form ("55"), which the contract's own script cannot read.
        assertEquals("0105", hex);
        assertEquals("05", StateSerializer.deserialize(BYTESTR, hex).get("blob"));
    }

    @Test
    void controlEmptyByteString() {
        String hex = StateSerializer.serialize(BYTESTR, Map.of("blob", ""));
        assertEquals("", StateSerializer.deserialize(BYTESTR, hex).get("blob"));
    }

    @Test
    void controlEmptyFieldListAndEmptyBlob() {
        assertTrue(StateSerializer.deserialize(List.of(), "").isEmpty());
    }

    @ParameterizedTest
    @ValueSource(ints = {75, 76, 300})
    void controlPushesOfEveryFramingWidthRoundTrip(int n) {
        String payload = rep("ab", n);
        String hex = StateSerializer.serialize(BYTESTR, Map.of("blob", payload));
        assertEquals(payload, StateSerializer.deserialize(BYTESTR, hex).get("blob"));
    }

    @ParameterizedTest
    @CsvSource({
        "PubKey,33", "Addr,20", "Ripemd160,20", "Sha256,32",
        "Point,64", "P256Point,64", "P384Point,96",
    })
    void controlEveryFixedWidthTypeAtItsExactWidth(String type, int width) {
        String payload = rep("7e", width);
        assertEquals(payload, StateSerializer.deserialize(List.of(f("v", type, 0)), payload).get("v"));
    }

    @Test
    void controlALegitimateContinuationStillRestores() {
        List<StateField> fields = List.of(f("count", "bigint", 0));
        RunarArtifact artifact = artifactWith(fields);
        String stateHex = StateSerializer.serialize(fields, Map.of("count", 5L));
        Map<String, Object> got = StateSerializer.extractFromScript(artifact, "51" + "6a" + stateHex);
        assertEquals(BigInteger.valueOf(5), got.get("count"));
    }

    // -----------------------------------------------------------------------
    // Null value for a raw fixed-width field — the four-way byte divergence.
    //
    // Java wrote String.valueOf(null) = "null", Go "<nil>", TS "undefined",
    // Python/Ruby "". None is valid hex; all four deploy a corrupt state
    // section, just differently. Refusing is the only answer that is the same
    // in every tier.
    // -----------------------------------------------------------------------

    @ParameterizedTest
    @ValueSource(strings = {"PubKey", "Addr", "Ripemd160", "Sha256", "Point", "P256Point", "P384Point"})
    void serializingANullRawFixedWidthValueIsRefused(String type) {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> StateSerializer.serialize(List.of(f("v", type, 0)), Map.of()));
        assertTrue(e.getMessage().toLowerCase().contains("no value"), e.getMessage());
    }
}

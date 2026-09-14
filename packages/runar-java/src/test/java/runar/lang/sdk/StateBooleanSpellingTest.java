package runar.lang.sdk;

import java.math.BigInteger;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import runar.lang.sdk.RunarArtifact.StateField;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * A mutable {@code boolean} state field is ONE raw byte — {@code 01} or {@code 00}.
 *
 * <p>The compiler spells the type {@code boolean}. {@code bool} appears nowhere in any
 * of the seven frontends, so an artifact's {@code stateFields} never carries it; the
 * SDKs that matched on {@code "bool"} alone were matching a spelling no compiler emits,
 * and every real boolean field fell through to their push-data default:
 *
 * <pre>
 * typescript  01           correct
 * ruby        01           correct
 * go          02 74727565  push-framed ASCII "true" — 3 bytes too long
 * java        02 74727565  same
 * python      00           right width, ALWAYS false
 * zig         00           same
 * rust        panic        as_bytes() on a Bool variant
 * </pre>
 *
 * <p>All five are fund-affecting. Java and Go deploy a state tail longer than the one
 * the script's own reader rebuilds, so {@code hash256(outputs)} can never match and the
 * first spend is impossible. Python and Zig deploy a well-formed tail that says
 * {@code false} whatever the caller passed, so the first call that sets the flag builds
 * a continuation the covenant rejects. Rust fails closed.
 *
 * <p>{@code BOOLEAN_SPELLING_GOLDEN} is byte-identical across all seven SDKs; every tier
 * carries the same literal and the same field list. The trailing {@code bigint} is
 * load-bearing: a boolean of the wrong WIDTH shifts it, so the record catches a length
 * error that a lone boolean field would hide.
 */
class StateBooleanSpellingTest {

    private static final List<StateField> FIELDS = List.of(
        new StateField("count", "bigint", 0, null, null),
        // The canonical spelling — the only one any compiler emits.
        new StateField("flag", "boolean", 1, null, null),
        // The alias. Several tiers accepted only this one; it must keep working.
        new StateField("alias", "bool", 2, null, null),
        new StateField("tail", "bigint", 3, null, null));

    private static Map<String, Object> values(boolean flag, boolean alias) {
        Map<String, Object> v = new LinkedHashMap<>();
        v.put("count", BigInteger.valueOf(7));
        v.put("flag", flag);
        v.put("alias", alias);
        v.put("tail", BigInteger.ONE);
        return v;
    }

    /** The one wire record every tier must reproduce byte for byte. */
    private static final String BOOLEAN_SPELLING_GOLDEN =
        "0700000000000000"      // bigint 7, NUM2BIN 8
        + "01"                  // boolean true  — 1 raw byte
        + "00"                  // bool    false — 1 raw byte
        + "0100000000000000";   // bigint 1, NUM2BIN 8

    private static final String FLIPPED_GOLDEN =
        "0700000000000000" + "00" + "01" + "0100000000000000";

    @Test
    void crossSdkGoldenSerializesByteForByte() {
        assertEquals(18, BOOLEAN_SPELLING_GOLDEN.length() / 2, "golden must be 18 bytes");
        assertEquals(BOOLEAN_SPELLING_GOLDEN, StateSerializer.serialize(FIELDS, values(true, false)));
    }

    @Test
    void oppositePolarityIsADifferentRecord() {
        assertEquals(FLIPPED_GOLDEN, StateSerializer.serialize(FIELDS, values(false, true)));
    }

    @Test
    void crossSdkGoldenDeserializesBackToEveryValue() {
        Map<String, Object> back = StateSerializer.deserialize(FIELDS, BOOLEAN_SPELLING_GOLDEN);
        assertEquals(BigInteger.valueOf(7), back.get("count"));
        assertEquals(Boolean.TRUE, back.get("flag"));
        assertEquals(Boolean.FALSE, back.get("alias"));
        assertEquals(BigInteger.ONE, back.get("tail"));
    }

    @Test
    void flippedRecordDeserializesToo() {
        Map<String, Object> back = StateSerializer.deserialize(FIELDS, FLIPPED_GOLDEN);
        assertEquals(Boolean.FALSE, back.get("flag"));
        assertEquals(Boolean.TRUE, back.get("alias"));
    }

    @Test
    void loneBooleanFieldIsExactlyOneByte() {
        List<StateField> one = List.of(new StateField("v", "boolean", 0, null, null));
        for (boolean value : new boolean[] { true, false }) {
            String want = value ? "01" : "00";
            assertEquals(want, StateSerializer.serialize(one, Map.of("v", value)), "boolean " + value);
            assertEquals(value, StateSerializer.deserialize(one, want).get("v"), "boolean " + value);
        }
    }
}

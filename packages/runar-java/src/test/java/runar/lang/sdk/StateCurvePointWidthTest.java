package runar.lang.sdk;

import java.math.BigInteger;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import runar.lang.sdk.RunarArtifact.StateField;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * {@code P256Point} (64) and {@code P384Point} (96) are FIXED-WIDTH RAW state fields.
 *
 * <p>All seven compilers emit them as fixed raw slices in the state tail, and
 * runar-lang's cast constructors hard-assert exactly those widths. The seven SDKs
 * used to omit both from their width tables, so they fell through to the push-data
 * default and deployed a state section 1 byte ({@code 0x40} direct push) or 2 bytes
 * ({@code OP_PUSHDATA1 0x60}) longer than the script's own on-chain reader expects.
 * The deploy succeeded and the FIRST spend failed with "OP_NUMEQUALVERIFY requires
 * the top stack item to be truthy" — funds locked.
 *
 * <p>{@code CROSS_SDK_GOLDEN} is byte-identical across all seven SDKs; every tier
 * carries the same literal and the same field list.
 */
class StateCurvePointWidthTest {

    private static String rep(String unit, int n) {
        return unit.repeat(n);
    }

    private static final List<StateField> FIELDS = List.of(
        new StateField("n", "bigint", 0, null, null),
        new StateField("flag", "bool", 1, null, null),
        new StateField("pk", "PubKey", 2, null, null),
        new StateField("h", "Sha256", 3, null, null),
        new StateField("ad", "Addr", 4, null, null),
        new StateField("pt", "Point", 5, null, null),
        new StateField("p256", "P256Point", 6, null, null),
        new StateField("p384", "P384Point", 7, null, null),
        new StateField("sig", "Sig", 8, null, null),
        new StateField("rab", "RabinSig", 9, null, null),
        new StateField("bs", "ByteString", 10, null, null));

    private static Map<String, Object> values() {
        Map<String, Object> v = new LinkedHashMap<>();
        v.put("n", BigInteger.ONE);
        v.put("flag", Boolean.TRUE);
        v.put("pk", "02" + rep("aa", 32));
        v.put("h", rep("bb", 32));
        v.put("ad", rep("cc", 20));
        v.put("pt", rep("dd", 64));
        v.put("p256", rep("11", 64));
        v.put("p384", rep("22", 96));
        v.put("sig", "3044" + rep("ee", 66));
        v.put("rab", rep("ff", 8));
        v.put("bs", "0011");
        return v;
    }

    /** The one wire record every tier must reproduce byte for byte. */
    private static final String CROSS_SDK_GOLDEN =
        "0100000000000000"                 // bigint 1, NUM2BIN 8
        + "01"                             // bool true
        + "02" + rep("aa", 32)             // PubKey    33 raw
        + rep("bb", 32)                    // Sha256    32 raw
        + rep("cc", 20)                    // Addr      20 raw
        + rep("dd", 64)                    // Point     64 raw
        + rep("11", 64)                    // P256Point 64 raw  <- was framed "40" + 64
        + rep("22", 96)                    // P384Point 96 raw  <- was framed "4c60" + 96
        + "44" + "3044" + rep("ee", 66)    // Sig        framed <len><data>
        + "08" + rep("ff", 8)              // RabinSig   framed <len><data>
        + "02" + "0011";                   // ByteString framed <len><data>

    @Test
    void crossSdkGoldenSerializesByteForByte() {
        assertEquals(399, CROSS_SDK_GOLDEN.length() / 2, "golden must be 399 bytes");
        assertEquals(CROSS_SDK_GOLDEN, StateSerializer.serialize(FIELDS, values()));
    }

    @Test
    void crossSdkGoldenDeserializesBackToEveryValue() {
        Map<String, Object> back = StateSerializer.deserialize(FIELDS, CROSS_SDK_GOLDEN);
        assertEquals(BigInteger.ONE, back.get("n"));
        assertEquals(Boolean.TRUE, back.get("flag"));
        Map<String, Object> in = values();
        for (String k : List.of("pk", "h", "ad", "pt", "p256", "p384", "sig", "rab", "bs")) {
            assertEquals(in.get(k), back.get(k), "field " + k);
        }
    }

    @Test
    void loneCurvePointFieldRoundTripsRaw() {
        record Case(String type, int size, String fill) { }
        for (Case c : List.of(new Case("P256Point", 64, "11"), new Case("P384Point", 96, "22"))) {
            List<StateField> one = List.of(new StateField("v", c.type(), 0, null, null));
            String v = rep(c.fill(), c.size());
            String hex = StateSerializer.serialize(one, Map.of("v", v));
            assertEquals(v, hex, c.type() + " must serialize raw");
            assertEquals(c.size(), hex.length() / 2, c.type() + " width");
            assertEquals(v, StateSerializer.deserialize(one, hex).get("v"), c.type() + " round-trip");
        }
    }

    @Test
    void controlsStayByteUnchanged() {
        record Raw(String type, int size) { }
        for (Raw c : List.of(new Raw("Point", 64), new Raw("PubKey", 33), new Raw("Sha256", 32))) {
            String v = rep("ab", c.size());
            assertEquals(v,
                StateSerializer.serialize(List.of(new StateField("v", c.type(), 0, null, null)),
                    Map.of("v", v)),
                c.type() + " control must stay raw");
        }
        for (String type : List.of("ByteString", "Sig", "RabinSig")) {
            String v = rep("ab", 64);
            assertEquals("40" + v,
                StateSerializer.serialize(List.of(new StateField("v", type, 0, null, null)),
                    Map.of("v", v)),
                type + " control must stay framed");
        }
    }
}

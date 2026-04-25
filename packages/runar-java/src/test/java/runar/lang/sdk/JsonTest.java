package runar.lang.sdk;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Direct exercise of the hand-rolled JSON parser/writer pair. Covers
 * primitive scalars, escaping, nested structures, the integer-fits
 * choice (Long vs BigInteger), and round-trip stability.
 */
class JsonTest {

    @Test
    void parsesPrimitiveScalars() {
        assertNull(Json.parse("null"));
        assertEquals(Boolean.TRUE, Json.parse("true"));
        assertEquals(Boolean.FALSE, Json.parse("false"));
        assertEquals("hello", Json.parse("\"hello\""));
        assertEquals(42L, Json.parse("42"));
        assertEquals(-7L, Json.parse("-7"));
    }

    @Test
    void parsesLargeIntegerAsBigInteger() {
        // Larger than Long.MAX_VALUE — must fall back to BigInteger.
        Object v = Json.parse("99999999999999999999999999999999");
        assertTrue(v instanceof BigInteger, "huge number must be BigInteger, got " + v.getClass());
        assertEquals(new BigInteger("99999999999999999999999999999999"), v);
    }

    @Test
    void parsesArray() {
        Object v = Json.parse("[1, 2, 3]");
        assertTrue(v instanceof List);
        @SuppressWarnings("unchecked")
        List<Object> l = (List<Object>) v;
        assertEquals(3, l.size());
        assertEquals(1L, l.get(0));
        assertEquals(2L, l.get(1));
        assertEquals(3L, l.get(2));
    }

    @Test
    void parsesObjectPreservingOrder() {
        Object v = Json.parse("{\"a\":1,\"b\":2,\"c\":3}");
        assertTrue(v instanceof Map);
        @SuppressWarnings("unchecked")
        Map<String, Object> m = (Map<String, Object>) v;
        // LinkedHashMap → keys appear in insertion order.
        assertArrayEquals(new String[]{"a", "b", "c"}, m.keySet().toArray(new String[0]));
    }

    @Test
    void parsesNestedStructure() {
        String src = "{\"items\":[{\"id\":1,\"tags\":[\"a\",\"b\"]},{\"id\":2,\"tags\":[]}]}";
        Object v = Json.parse(src);
        @SuppressWarnings("unchecked")
        Map<String, Object> root = (Map<String, Object>) v;
        @SuppressWarnings("unchecked")
        List<Object> items = (List<Object>) root.get("items");
        assertEquals(2, items.size());
        @SuppressWarnings("unchecked")
        Map<String, Object> first = (Map<String, Object>) items.get(0);
        assertEquals(1L, first.get("id"));
        @SuppressWarnings("unchecked")
        List<Object> tags = (List<Object>) first.get("tags");
        assertEquals(List.of("a", "b"), tags);
    }

    @Test
    void parsesEscapedStringChars() {
        assertEquals("a\"b", Json.parse("\"a\\\"b\""));
        assertEquals("a\\b", Json.parse("\"a\\\\b\""));
        assertEquals("a\nb", Json.parse("\"a\\nb\""));
        assertEquals("a\tb", Json.parse("\"a\\tb\""));
    }

    @Test
    void rejectsTrailingGarbage() {
        assertThrows(IllegalArgumentException.class, () -> Json.parse("42 trailing"));
    }

    @Test
    void rejectsUnterminatedString() {
        assertThrows(RuntimeException.class, () -> Json.parse("\"unterminated"));
    }

    @Test
    void writeRoundTripsScalars() {
        assertEquals("null", JsonWriter.write(null));
        assertEquals("true", JsonWriter.write(Boolean.TRUE));
        assertEquals("false", JsonWriter.write(Boolean.FALSE));
        assertEquals("42", JsonWriter.write(42L));
        assertEquals("-7", JsonWriter.write(-7L));
        assertEquals("\"hello\"", JsonWriter.write("hello"));
    }

    @Test
    void writeEscapesSpecialChars() {
        assertEquals("\"a\\\"b\"", JsonWriter.write("a\"b"));
        assertEquals("\"a\\\\b\"", JsonWriter.write("a\\b"));
        assertEquals("\"a\\nb\"", JsonWriter.write("a\nb"));
    }

    @Test
    void writeArrayAndObject() {
        assertEquals("[1,2,3]", JsonWriter.write(List.of(1L, 2L, 3L)));
        // LinkedHashMap preserves order so the output is deterministic.
        java.util.LinkedHashMap<String, Object> m = new java.util.LinkedHashMap<>();
        m.put("a", 1L);
        m.put("b", "x");
        assertEquals("{\"a\":1,\"b\":\"x\"}", JsonWriter.write(m));
    }

    @Test
    void parseWriteRoundTripPreservesShape() {
        String input = "{\"a\":1,\"b\":[2,3],\"c\":\"hi\"}";
        String roundTripped = JsonWriter.write(Json.parse(input));
        assertEquals(input, roundTripped);
    }
}

package runar.lang.sdk;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import runar.lang.sdk.RunarArtifact.StateField;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * F-035: {@code RabinPubKey} / {@code RabinSig} state fields are a bare 8-byte
 * OP_NUM2BIN word, exactly like {@code bigint}. Both are bigint aliases and every
 * compiler writes and reads them that way in the state section (the compiler is
 * canonical, user decision D2). The SDK width table omitted both, so they fell to
 * the push-data default, which framed {@code String.valueOf(BigInteger)} — the
 * DECIMAL text of the number — as if it were hex.
 *
 * <p>{@code RABIN_STATE_GOLDEN} is hand-derived and byte-identical across all
 * seven SDKs (the same three values are the {@code state-rabin} sdk-output
 * fixture):
 * <pre>
 *   RabinPubKey 0x1234567890ABCDEF -> efcdab9078563412
 *   RabinSig    -1000000007        -> 07ca9a3b00000080
 *   bigint      3                  -> 0300000000000000
 * </pre>
 *
 * <p>Proves: the Java codec writes and reads that layout. Does not prove the
 * script accepts it (packages/runar-testing f035-rabin-state-spend.test.ts).
 */
class StateRabinWidthTest {

    private static final String RABIN_STATE_GOLDEN =
        "efcdab9078563412" + "07ca9a3b00000080" + "0300000000000000";

    private static final List<StateField> FIELDS = List.of(
        new StateField("oracleKey", "RabinPubKey", 0, null, null),
        new StateField("lastSig", "RabinSig", 1, null, null),
        new StateField("count", "bigint", 2, null, null));

    private static final Map<String, Object> VALUES = Map.of(
        "oracleKey", new BigInteger("1234567890ABCDEF", 16),
        "lastSig", BigInteger.valueOf(-1000000007L),
        "count", BigInteger.valueOf(3));

    @Test
    void rabinFieldsSerializeAsNum2Bin8() {
        assertEquals(RABIN_STATE_GOLDEN, StateSerializer.serialize(FIELDS, VALUES));
    }

    @Test
    void rabinFieldsDeserializeBack() {
        assertEquals(VALUES, StateSerializer.deserialize(FIELDS, RABIN_STATE_GOLDEN));
    }

    @Test
    void rabinValueOutsideTheWordIsRefused() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () ->
            StateSerializer.serialize(List.of(new StateField("k", "RabinPubKey", 0, null, null)),
                Map.of("k", BigInteger.ONE.shiftLeft(63))));
        assertTrue(e.getMessage().contains("does not fit"), e.getMessage());
    }
}

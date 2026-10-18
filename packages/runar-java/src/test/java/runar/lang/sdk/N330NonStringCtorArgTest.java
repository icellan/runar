package runar.lang.sdk;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * N-330: a non-String ByteString-family constructor arg must be encoded as the
 * raw bytes it is ({@code byte[]}) or refused with
 * {@link InvalidConstructorArgException}. Before, {@code encodeConstructorArg}
 * fell back to {@code String.valueOf(value)}, so a {@code byte[]} became
 * {@code "[B@1b2c3d"}, and a Long was encoded as a script number.
 *
 * <p>Proves: {@code byte[]} (scalar and FixedArray leaf) yields the same
 * locking script as the equivalent hex string; null, Long, Integer,
 * BigInteger, Boolean, Double and a List of numbers are refused with the
 * shared diagnostic.
 * Does NOT prove: width checks, method-call args or on-chain spendability.
 */
class N330NonStringCtorArgTest {

    private static RunarArtifact artifact(String type, String fixedArrayJson) {
        String fa = fixedArrayJson == null ? "" : ",\"fixedArray\":" + fixedArrayJson;
        return RunarArtifact.fromJson(
            "{\"version\":\"runar-v0.1.0\",\"compilerVersion\":\"0.1.0\",\"contractName\":\"N330\","
                + "\"abi\":{\"constructor\":{\"params\":[{\"name\":\"owner\",\"type\":\"" + type + "\"" + fa + "}]},"
                + "\"methods\":[{\"name\":\"noop\",\"params\":[],\"isPublic\":true}]},"
                + "\"script\":\"00\",\"asm\":\"\",\"stateFields\":[],"
                + "\"constructorSlots\":[{\"paramIndex\":0,\"byteOffset\":0}]}");
    }

    private static List<Object> one(Object arg) {
        List<Object> l = new ArrayList<>();
        l.add(arg);
        return l;
    }

    private static final String FA =
        "{\"elementType\":\"Addr\",\"length\":2,\"syntheticNames\":[\"owner__0\",\"owner__1\"]}";

    @Test
    void rawBytesEncodeAsThoseBytes() {
        byte[] raw = {(byte) 0x9a, 0x1c, 0x78, (byte) 0xa5};
        String viaBytes = new RunarContract(artifact("ByteString", null), one(raw)).lockingScript();
        String viaHex = new RunarContract(artifact("ByteString", null), one("9a1c78a5")).lockingScript();
        assertEquals(viaHex, viaBytes);
    }

    @Test
    void rawBytesFixedArrayLeafEncodesAsThoseBytes() {
        byte[] raw = {(byte) 0x9a, 0x1c, 0x78, (byte) 0xa5};
        String viaBytes = new RunarContract(artifact("FixedArray<Addr, 2>", FA),
            one(Arrays.asList(raw, "9a1c78a5"))).lockingScript();
        String viaHex = new RunarContract(artifact("FixedArray<Addr, 2>", FA),
            one(List.of("9a1c78a5", "9a1c78a5"))).lockingScript();
        assertEquals(viaHex, viaBytes);
    }

    @Test
    void nonStringArgsAreRefused() {
        Object[] bad = {null, 5L, 5, BigInteger.TEN, Boolean.TRUE, 1.5d, List.of(1, 2, 3), new Object()};
        for (Object arg : bad) {
            InvalidConstructorArgException e = assertThrows(
                InvalidConstructorArgException.class,
                () -> new RunarContract(artifact("ByteString", null), one(arg)),
                String.valueOf(arg));
            assertEquals(
                "RunarContract: constructor arg 'owner' (ByteString) of N330 must be an even-length hex string",
                e.getMessage());
        }
    }

    @Test
    void nullFixedArrayLeafIsRefused() {
        assertThrows(InvalidConstructorArgException.class,
            () -> new RunarContract(artifact("FixedArray<Addr, 2>", FA), one(Arrays.asList("aabb", null))));
    }
}

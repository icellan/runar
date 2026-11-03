package runar.lang.sdk;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * N-073: a fixed-width ByteString-family constructor arg must have its declared
 * width (Addr/Ripemd160 20, Sha256 32, PubKey 33, Point/P256Point 64,
 * P384Point 96), with N-045's message. {@code fromUtxo}'s internal restore
 * path is unaffected.
 *
 * <p>Proves: a 33-byte Sha256 and a 19-byte Addr (scalar, byte[], FixedArray
 * leaf) are refused with {@link InvalidConstructorArgException} carrying the
 * N-045 wording; correct widths are accepted; ByteString takes any length;
 * {@code fromUtxo} restores.
 * Does NOT prove: method-call or state value widths (N-045), on-chain
 * spendability, or that the restore bypass is unreachable by user input.
 */
class N073CtorArgWidthTest {

    private static RunarArtifact artifact(String type, String fixedArrayJson) {
        String fa = fixedArrayJson == null ? "" : ",\"fixedArray\":" + fixedArrayJson;
        return RunarArtifact.fromJson(
            "{\"version\":\"runar-v0.1.0\",\"compilerVersion\":\"0.1.0\",\"contractName\":\"N073\","
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

    private static String hex(int n) {
        return "ab".repeat(n);
    }

    private static final String FA =
        "{\"elementType\":\"Addr\",\"length\":2,\"syntheticNames\":[\"owner__0\",\"owner__1\"]}";

    @Test
    void wrongWidthSha256IsRefusedWithN045Message() {
        InvalidConstructorArgException e = assertThrows(InvalidConstructorArgException.class,
            () -> new RunarContract(artifact("Sha256", null), one(hex(33))));
        assertTrue(e.getMessage().contains(
            "constructor arg 'owner' (Sha256) must be exactly 32 bytes of hex, got 33 bytes"), e.getMessage());
    }

    @Test
    void wrongWidthAddrIsRefused() {
        assertThrows(InvalidConstructorArgException.class,
            () -> new RunarContract(artifact("Addr", null), one(hex(19))));
        assertThrows(InvalidConstructorArgException.class,
            () -> new RunarContract(artifact("Addr", null), one(new byte[19])));
    }

    @Test
    void wrongWidthFixedArrayLeafIsRefused() {
        assertThrows(InvalidConstructorArgException.class,
            () -> new RunarContract(artifact("FixedArray<Addr, 2>", FA), one(List.of(hex(20), hex(19)))));
    }

    @Test
    void correctWidthIsAcceptedAndOneLessRefused() {
        Map<String, Integer> widths = Map.of(
            "Addr", 20, "Ripemd160", 20, "Sha256", 32, "PubKey", 33,
            "Point", 64, "P256Point", 64, "P384Point", 96);
        widths.forEach((type, n) -> {
            assertDoesNotThrow(() -> new RunarContract(artifact(type, null), one(hex(n))).lockingScript());
            assertThrows(InvalidConstructorArgException.class,
                () -> new RunarContract(artifact(type, null), one(hex(n - 1))), type);
        });
        assertDoesNotThrow(() -> new RunarContract(artifact("ByteString", null), one(hex(3))));
    }

    @Test
    void fromUtxoStillRestores() {
        RunarArtifact a = artifact("Addr", null);
        String script = new RunarContract(a, one(hex(20))).lockingScript();
        RunarContract c = RunarContract.fromUtxo(a, new UTXO("00".repeat(32), 0, 1L, script));
        assertEquals(script, c.lockingScript());
    }
}

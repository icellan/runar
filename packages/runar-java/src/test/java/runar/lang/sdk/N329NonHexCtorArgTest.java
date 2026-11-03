package runar.lang.sdk;

import java.util.List;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * N-329: a ByteString-family constructor arg that is not an even-length hex
 * string must be refused at construction with a typed exception, not spliced
 * into the locking script as raw text (a push header sized for the raw bytes
 * followed by non-hex characters, with no error).
 *
 * <p>Proves: {@code new RunarContract} throws {@link InvalidConstructorArgException}
 * (shared diagnostic) for raw non-hex Addr text, odd-length hex and a non-hex
 * leaf in a {@code FixedArray<Addr, 2>} list; valid hex (either case, empty)
 * is accepted and {@code lockingScript()} is hex-only.
 * Does NOT prove: width checks (a 3-byte Addr is accepted here) or on-chain
 * spendability.
 */
class N329NonHexCtorArgTest {

    private static RunarArtifact artifact(String type, String fixedArrayJson) {
        String fa = fixedArrayJson == null ? "" : ",\"fixedArray\":" + fixedArrayJson;
        return RunarArtifact.fromJson(
            "{\"version\":\"runar-v0.1.0\",\"compilerVersion\":\"0.1.0\",\"contractName\":\"N329\","
                + "\"abi\":{\"constructor\":{\"params\":[{\"name\":\"owner\",\"type\":\"" + type + "\"" + fa + "}]},"
                + "\"methods\":[{\"name\":\"noop\",\"params\":[],\"isPublic\":true}]},"
                + "\"script\":\"00\",\"asm\":\"\",\"stateFields\":[],"
                + "\"constructorSlots\":[{\"paramIndex\":0,\"byteOffset\":0}]}");
    }

    private static void assertRefused(String type, String fa, Object arg) {
        InvalidConstructorArgException e = assertThrows(
            InvalidConstructorArgException.class,
            () -> new RunarContract(artifact(type, fa), List.of(arg)));
        assertEquals(
            "RunarContract: constructor arg 'owner' (" + type + ") of N329 must be an even-length hex string",
            e.getMessage());
    }

    @Test
    void nonHexByteStringFamilyArgsAreRefused() {
        StringBuilder raw = new StringBuilder();
        for (int i = 0x80; i < 0x94; i++) raw.append((char) i);
        assertRefused("Addr", null, raw.toString());
        assertRefused("ByteString", null, "abc");
        assertRefused("PubKey", null, "zz");
    }

    @Test
    void nonHexFixedArrayLeafIsRefused() {
        String fa = "{\"elementType\":\"Addr\",\"length\":2,\"syntheticNames\":[\"owner__0\",\"owner__1\"]}";
        assertRefused("FixedArray<Addr, 2>", fa, List.of("aabb", "not-hex!"));
    }

    @Test
    void hexByteStringArgsAreAccepted() {
        for (String arg : new String[] {"9a1c78a5", "9A1C78A5", ""}) {
            RunarContract c = new RunarContract(artifact("ByteString", null), List.of(arg));
            assertTrue(ScriptUtils.isHexBytes(c.lockingScript()), arg);
        }
    }
}

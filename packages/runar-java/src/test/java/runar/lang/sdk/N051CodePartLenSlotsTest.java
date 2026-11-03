package runar.lang.sdk;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * N-051 ("TaffyTail") — the SDK writes the deployed code-part length into every
 * {@code codePartLenSlots} field.
 *
 * <p>The compiler pins {@code SIZE(_codePart)} with an EQUALITY
 * ({@code OP_DUP <04 LL LL LL LL> OP_BIN2NUM OP_NUMEQUAL OP_VERIFY}). When a
 * variable-width readonly constructor arg is baked into the code, the deployed
 * length is only known at deploy time, so the artifact names the 4-byte field
 * in {@code codePartLenSlots} and the SDK fills it with the length of the code
 * part it actually deploys — inscription envelope included.
 *
 * <p>Fixture: the TypeScript reference compiler's TaffyTailVault artifact
 * (fold OFF, slot at template byte 959) and the hex the TypeScript SDK builds
 * from it ({@code taffytail-vault-expected.json}). The owner slot at template
 * byte 465 precedes the length field and the tag slot at 1113 follows it, so
 * the resolved offset exercises the "earlier substitutions only" shift.
 */
class N051CodePartLenSlotsTest {

    private static String resource(String rel) throws Exception {
        try (InputStream in = N051CodePartLenSlotsTest.class.getClassLoader().getResourceAsStream(rel)) {
            assertNotNull(in, "test resource not found on classpath: " + rel);
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static String artifactJson() throws Exception {
        return resource("artifacts/taffytail-vault.runar.json");
    }

    private static Map<String, Object> expected() throws Exception {
        return Json.asObject(Json.parse(resource("artifacts/taffytail-vault-expected.json")));
    }

    private static List<Object> args(Map<String, Object> exp) {
        List<Object> out = new ArrayList<>();
        for (Object o : (List<?>) exp.get("constructorArgs")) out.add(Json.asString(o));
        return out;
    }

    private static Inscription inscription(Map<String, Object> exp) {
        Map<String, Object> i = Json.asObject(exp.get("inscription"));
        return new Inscription(Json.asString(i.get("contentType")), Json.asString(i.get("data")));
    }

    /** Replace the artifact's codePartLenSlots array with {@code replacement} (a JSON value). */
    private static String withSlots(String json, String replacement) {
        String out = json.replaceFirst(
            "\"codePartLenSlots\"\\s*:\\s*\\[[^\\]]*\\]", "\"codePartLenSlots\": " + replacement);
        assertNotEquals(json, out, "fixture must carry a codePartLenSlots field");
        return out;
    }

    @Test
    void artifactParsesCodePartLenSlots() throws Exception {
        RunarArtifact artifact = RunarArtifact.fromJson(artifactJson());
        assertEquals(List.of(new RunarArtifact.CodePartLenSlot(959)), artifact.codePartLenSlots());
        assertEquals(List.of(), RunarArtifact.fromJson(
            withSlots(artifactJson(), "[]")).codePartLenSlots());
    }

    @Test
    void builtCodePartAndLockingScriptMatchTheTypeScriptSdk() throws Exception {
        Map<String, Object> exp = expected();
        RunarArtifact artifact = RunarArtifact.fromJson(artifactJson());
        RunarContract contract = new RunarContract(artifact, args(exp));

        String codePart = ContractScript.renderCodePart(artifact, args(exp), null);
        assertEquals(Json.asString(exp.get("codePartHex")), codePart);
        assertEquals(Json.asInt(exp.get("codePartLen")), codePart.length() / 2);
        assertEquals(Json.asString(exp.get("lockingScriptHex")), contract.lockingScript());
    }

    @Test
    void inscriptionIsAcceptedAndCountedInThePinnedLength() throws Exception {
        Map<String, Object> exp = expected();
        RunarArtifact artifact = RunarArtifact.fromJson(artifactJson());
        RunarContract contract = new RunarContract(artifact, args(exp));

        // The deploy-time pin is patched to the inscribed length, so the N-043
        // guard must accept the envelope rather than refuse it.
        assertSame(contract, contract.withInscription(inscription(exp)));

        String inscribed = ContractScript.renderCodePart(artifact, args(exp), inscription(exp));
        assertEquals(Json.asString(exp.get("inscribedCodePartHex")), inscribed);
        assertEquals(Json.asInt(exp.get("inscribedCodePartLen")), inscribed.length() / 2);
        assertTrue(contract.lockingScript().startsWith(inscribed + "6a"),
            "inscribed locking script must be code part (envelope included) + OP_RETURN + state");
    }

    /**
     * Without the slot the template's compile-time value stays in the field —
     * it is an exact pin as far as the SDK knows, and it does not match the
     * inscribed code part. Refuse, exactly as for any exact compile-time pin.
     */
    @Test
    void anUnpatchedPinStillRefusesAnInscription() throws Exception {
        Map<String, Object> exp = expected();
        RunarArtifact artifact = RunarArtifact.fromJson(withSlots(artifactJson(), "[]"));
        RunarContract contract = new RunarContract(artifact, args(exp));

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> contract.withInscription(inscription(exp)));
        assertTrue(e.getMessage().contains("pins SIZE(_codePart) =="), e.getMessage());
        assertNull(contract.inscription());
    }

    @Test
    void corruptedSlotOffsetIsRefused() throws Exception {
        Map<String, Object> exp = expected();
        for (int bad : List.of(958, 960, 0)) {
            RunarArtifact artifact = RunarArtifact.fromJson(
                withSlots(artifactJson(), "[{\"byteOffset\": " + bad + "}]"));
            RuntimeException e = assertThrows(RuntimeException.class,
                () -> ContractScript.renderCodePart(artifact, args(exp), null),
                "byteOffset " + bad + " must be refused");
            assertTrue(e.getMessage().contains("does not point at a verify_code_part_len length field"),
                e.getMessage());
        }
    }
}

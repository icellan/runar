package runar.lang.sdk;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import runar.lang.sdk.RunarArtifact.ABI;
import runar.lang.sdk.RunarArtifact.ABIConstructor;
import runar.lang.sdk.RunarArtifact.ABIParam;
import runar.lang.sdk.RunarArtifact.ConstructorSlot;
import runar.lang.sdk.RunarArtifact.StateField;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Splice-correctness tests for {@link ContractScript}.
 *
 * <p>The locking-script template carries {@code OP_0} placeholders
 * (1 byte = {@code 0x00}) at recorded byte offsets. Renderer must
 * replace each placeholder with the proper push of the corresponding
 * constructor argument, append optional inscription envelope, and
 * append {@code OP_RETURN || serialised state} for stateful contracts.
 */
class ContractScriptTest {

    private static ABI abi(List<ABIParam> ctorParams) {
        return new ABI(new ABIConstructor(ctorParams), List.of());
    }

    private static ABIParam param(String name, String type) {
        return new ABIParam(name, type, null);
    }

    /** Stateless template with one OP_0 placeholder at byte 1, ready to receive a 20-byte addr push. */
    private static RunarArtifact statelessOnePlaceholder() {
        // a9 [00 placeholder] 7c 7c 9c 69 — same shape as the basic-p2pkh fixture
        return new RunarArtifact(
            "v0", "0", "Test",
            abi(List.of(param("pubKeyHash", "Addr"))),
            "a9007c7c9c69",
            "OP_HASH160 OP_0 OP_SWAP OP_SWAP OP_NUMEQUAL OP_VERIFY",
            null,
            List.of(),
            List.of(new ConstructorSlot(0, 1)),
            List.of(),
            null,
            null);
    }

    @Test
    void splicesByteStringConstructorArg() {
        RunarArtifact a = statelessOnePlaceholder();
        // 20-byte hash160 of a known pubkey.
        String hash = "751e76e8199196d454941c45d1b3a323f1433bd6";
        String script = ContractScript.renderLockingScript(a, List.of(hash), Map.of());
        // Expect: a9 [PUSH20 || hash] 7c 7c 9c 69 (placeholder replaced with 14-byte push of 20).
        assertEquals("a914" + hash + "7c7c9c69", script);
    }

    @Test
    void splicesBigIntegerScriptNumberArg() {
        RunarArtifact a = new RunarArtifact(
            "v0", "0", "Test",
            abi(List.of(param("count", "bigint"))),
            "76007c", // OP_DUP OP_0 OP_SWAP — placeholder at byte 1
            "asm",
            null,
            List.of(),
            List.of(new ConstructorSlot(0, 1)),
            List.of(),
            null,
            null);

        // Small positive: 5 → OP_5 (0x55). 1-byte slot, 1-byte replacement.
        String script = ContractScript.renderLockingScript(a, List.of(BigInteger.valueOf(5)), Map.of());
        assertEquals("76557c", script);
    }

    @Test
    void splicesBooleanArg() {
        RunarArtifact a = new RunarArtifact(
            "v0", "0", "Test",
            abi(List.of(param("active", "bool"))),
            "76007c",
            "asm",
            null,
            List.of(),
            List.of(new ConstructorSlot(0, 1)),
            List.of(),
            null,
            null);

        String trueScript  = ContractScript.renderLockingScript(a, List.of(Boolean.TRUE),  Map.of());
        String falseScript = ContractScript.renderLockingScript(a, List.of(Boolean.FALSE), Map.of());
        assertEquals("76517c", trueScript);   // OP_1 = 0x51
        assertEquals("76007c", falseScript);  // OP_0 = 0x00
    }

    @Test
    void multipleSplicesOrderedDescendingPreservesOffsets() {
        // Two placeholders at offsets 1 and 4. Encodings of different widths
        // would shift earlier offsets if applied left-to-right; descending
        // order keeps them stable.
        RunarArtifact a = new RunarArtifact(
            "v0", "0", "Test",
            abi(List.of(param("a", "Addr"), param("b", "bigint"))),
            "ab00cd00ef",  // ab [00 placeholder@1] cd [00 placeholder@3] ef  — width 5
            "asm",
            null,
            List.of(),
            List.of(new ConstructorSlot(0, 1), new ConstructorSlot(1, 3)),
            List.of(),
            null,
            null);

        String hash = "751e76e8199196d454941c45d1b3a323f1433bd6";
        String script = ContractScript.renderLockingScript(a, List.of(hash, BigInteger.valueOf(7)), Map.of());
        // After splice: ab [14<hash>] cd [57] ef
        assertEquals("ab14" + hash + "cd57ef", script);
    }

    @Test
    void appendsStateSerializationForStatefulContract() {
        RunarArtifact a = new RunarArtifact(
            "v0", "0", "Test",
            abi(List.of()),
            "76", // template
            "asm",
            null,
            List.of(new StateField("count", "bigint", 0, null, null)),
            List.of(),
            List.of(),
            null,
            null);

        String script = ContractScript.renderLockingScript(a, List.of(), Map.of("count", BigInteger.valueOf(7)));
        // Expect: code (76) || OP_RETURN (6a) || state-encoded count.
        // StateSerializer encodes bigint state as 8-byte LE (matches Go SDK).
        assertTrue(script.startsWith("766a"), "script must start with code+OP_RETURN, got " + script);
        // 7 little-endian over 8 bytes → 07 00 ... 00.
        assertEquals("766a0700000000000000", script);
    }

    @Test
    void injectsInscriptionEnvelopeBeforeStateForStateful() {
        RunarArtifact a = new RunarArtifact(
            "v0", "0", "Test",
            abi(List.of()),
            "76", "asm", null,
            List.of(new StateField("c", "bigint", 0, null, null)),
            List.of(), List.of(), null, null);

        Inscription ins = new Inscription("text/plain", "68656c6c6f"); // "hello"
        // Use the explicit overload that accepts an inscription.
        String script = ContractScript.renderLockingScript(
            a, List.of(), Map.of("c", BigInteger.ZERO), ins);

        // Inscription envelope appears AFTER code, BEFORE the trailing OP_RETURN+state.
        String envelope = ins.toEnvelopeHex();
        int envIdx = script.indexOf(envelope);
        int stateIdx = script.lastIndexOf("6a");
        assertTrue(envIdx > 0, "envelope must be present in rendered script");
        assertTrue(stateIdx > envIdx, "state OP_RETURN must come after the envelope");
    }

    @Test
    void extractCodePartStripsAfterLastOpReturn() {
        // code: 76aa, then OP_RETURN, then state push: 6a + 0107
        String full = "76aa6a0107";
        String code = ContractScript.extractCodePart(full);
        assertEquals("76aa", code);
    }

    @Test
    void extractCodePartReturnsFullScriptWhenNoOpReturn() {
        String full = "76aa55";
        assertEquals(full, ContractScript.extractCodePart(full));
    }

    @Test
    void encodeConstructorArgZero() {
        // Bare zero must become "00" (OP_0) regardless of declared type.
        assertEquals("00", ContractScript.encodeConstructorArg(BigInteger.ZERO, "bigint"));
    }

    @Test
    void encodeConstructorArgNegative() {
        // -1 → OP_1NEGATE = 0x4f
        assertEquals("4f", ContractScript.encodeConstructorArg(BigInteger.valueOf(-1), "bigint"));
    }

    @Test
    void encodeConstructorArgNumberInStringDecodesAsScriptNumber() {
        // String "42" with type "bigint" → script number push.
        assertEquals(ContractScript.encodeConstructorArg(BigInteger.valueOf(42), "bigint"),
                     ContractScript.encodeConstructorArg("42", "bigint"));
    }

    @Test
    void encodeConstructorArgStringHexFallsBackToPushData() {
        String hex = "751e76e8199196d454941c45d1b3a323f1433bd6";
        // ByteString slot type → encoded as raw push of the hex bytes (20 → 0x14 length prefix).
        assertEquals("14" + hex, ContractScript.encodeConstructorArg(hex, "ByteString"));
    }

    @Test
    void emptyConstructorSlotsEmitsTemplateUnchanged() {
        RunarArtifact a = new RunarArtifact(
            "v0", "0", "Plain",
            abi(List.of()),
            "76aa55",
            "asm", null,
            List.of(), List.of(), List.of(), null, null);
        assertEquals("76aa55", ContractScript.renderLockingScript(a, List.of(), Map.of()));
    }
}

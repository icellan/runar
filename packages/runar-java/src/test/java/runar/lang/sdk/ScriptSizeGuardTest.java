package runar.lang.sdk;

import java.util.List;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Item 8 — ScriptSizeExceededError at SDK entry points (Java).
 *
 * <p>Verifies that deploy/call/provider entry points reject scripts that
 * exceed {@link InputLimits#MAX_SCRIPT_BYTES} with a typed
 * {@link ScriptSizeExceededError} BEFORE any signing / broadcast work
 * happens.
 */
class ScriptSizeGuardTest {

    private static String oversizedScriptHex() {
        return "51".repeat(InputLimits.MAX_SCRIPT_BYTES + 1);
    }

    private static String atLimitScriptHex() {
        return "51".repeat(InputLimits.MAX_SCRIPT_BYTES);
    }

    private static RunarArtifact makeArtifact(String scriptHex, String contractName,
                                              List<RunarArtifact.ABIMethod> methods) {
        String methodsJson = methods.isEmpty()
            ? "[]"
            : "[" + String.join(",", methods.stream().map(m ->
                "{\"name\":\"" + m.name() + "\",\"params\":[],\"isPublic\":" + m.isPublic() + "}"
            ).toList()) + "]";
        String json =
            "{"
            + "\"version\":\"runar-v0.1.0\","
            + "\"compilerVersion\":\"0.1.0\","
            + "\"contractName\":\"" + contractName + "\","
            + "\"script\":\"" + scriptHex + "\","
            + "\"asm\":\"\","
            + "\"abi\":{\"constructor\":{\"params\":[]},\"methods\":" + methodsJson + "},"
            + "\"buildTimestamp\":\"2026-05-18T00:00:00.000Z\""
            + "}";
        return RunarArtifact.fromJson(json);
    }

    // -------------------------------------------------------------------------
    // deploy()
    // -------------------------------------------------------------------------

    @Test
    void deployRejectsOversizedScript() {
        RunarArtifact artifact = makeArtifact(oversizedScriptHex(), "OversizedContract", List.of());
        RunarContract contract = new RunarContract(artifact, List.of());
        MockProvider provider = new MockProvider();
        provider.addUtxo("00".repeat(20), new UTXO("aa".repeat(32), 0, 100_000L,
            "76a914" + "00".repeat(20) + "88ac"));
        MockSigner signer = new MockSigner();

        ScriptSizeExceededError err = assertThrows(
            ScriptSizeExceededError.class,
            () -> contract.deploy(provider, signer, 1_000L)
        );

        assertEquals(InputLimits.MAX_SCRIPT_BYTES, err.limit());
        assertEquals(InputLimits.MAX_SCRIPT_BYTES + 1, err.actual());
        assertTrue(err.context().contains("OversizedContract.deploy"),
            "context missing: " + err.context());
        assertTrue(err.getMessage().contains("limit=" + InputLimits.MAX_SCRIPT_BYTES));
        assertTrue(err.getMessage().contains("actual=" + (InputLimits.MAX_SCRIPT_BYTES + 1)));

        // No broadcast should have happened — guard fires BEFORE signing/broadcast.
        assertEquals(0, provider.getBroadcastedTxs().size(),
            "no broadcasts after rejected deploy");
    }

    // -------------------------------------------------------------------------
    // call()
    // -------------------------------------------------------------------------

    @Test
    void callRejectsOversizedCurrentUtxoScript() {
        // Use fromUtxo() to simulate a reconnect with a poisoned (oversized)
        // locking script. Avoids needing to actually deploy first.
        RunarArtifact artifact = makeArtifact("51", "OversizedContract",
            List.of(new RunarArtifact.ABIMethod("spend", List.of(), true, null)));
        UTXO poisoned = new UTXO("aa".repeat(32), 0, 50_000L, oversizedScriptHex());
        RunarContract contract = RunarContract.fromUtxo(artifact, poisoned);

        MockProvider provider = new MockProvider();
        provider.addUtxo("00".repeat(20), new UTXO("bb".repeat(32), 0, 100_000L,
            "76a914" + "00".repeat(20) + "88ac"));
        MockSigner signer = new MockSigner();

        ScriptSizeExceededError err = assertThrows(
            ScriptSizeExceededError.class,
            () -> contract.call("spend", List.of(), null, provider, signer)
        );

        assertEquals(InputLimits.MAX_SCRIPT_BYTES, err.limit());
        assertEquals(InputLimits.MAX_SCRIPT_BYTES + 1, err.actual());
        assertTrue(err.context().contains("OversizedContract.call(spend)"),
            "context missing: " + err.context());

        assertEquals(0, provider.getBroadcastedTxs().size(),
            "no broadcasts after rejected call");
    }

    // -------------------------------------------------------------------------
    // MockProvider — listUtxos / getUtxo
    // -------------------------------------------------------------------------

    @Test
    void mockProviderListUtxosRejectsOversizedScript() {
        MockProvider provider = new MockProvider();
        provider.addUtxo("addr", new UTXO("cc".repeat(32), 0, 1_000L, oversizedScriptHex()));

        ScriptSizeExceededError err = assertThrows(
            ScriptSizeExceededError.class,
            () -> provider.listUtxos("addr")
        );
        assertEquals(InputLimits.MAX_SCRIPT_BYTES, err.limit());
        assertEquals(InputLimits.MAX_SCRIPT_BYTES + 1, err.actual());
        assertTrue(err.context().contains("MockProvider.listUtxos"),
            "context missing: " + err.context());
    }

    @Test
    void mockProviderGetUtxoRejectsOversizedScript() {
        MockProvider provider = new MockProvider();
        UTXO poisoned = new UTXO("dd".repeat(32), 0, 1_000L, oversizedScriptHex());
        provider.addUtxo("addr", poisoned);

        ScriptSizeExceededError err = assertThrows(
            ScriptSizeExceededError.class,
            () -> provider.getUtxo(poisoned.txid(), 0)
        );
        assertTrue(err.context().contains("MockProvider.getUtxo"),
            "context missing: " + err.context());
    }

    @Test
    void atLimitScriptPassesProviderGuard() {
        MockProvider provider = new MockProvider();
        provider.addUtxo("addr", new UTXO("ee".repeat(32), 0, 1_000L, atLimitScriptHex()));
        List<UTXO> utxos = provider.listUtxos("addr");
        assertEquals(1, utxos.size());
        assertEquals(InputLimits.MAX_SCRIPT_BYTES * 2, utxos.get(0).scriptHex().length());
    }
}

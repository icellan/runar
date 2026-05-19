package runar.lang.sdk;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * R-6 — SDK consumer support for intent-intrinsic auto-injected witness
 * params ({@code _prevOutScript_<i>}, {@code _serialisedOutputs}).
 *
 * <p>Covers:
 * <ul>
 *   <li>filter: auto-injected witness params are NOT counted as user args
 *   <li>setters: {@code setPrevOutScript} / {@code setSerialisedOutputs}
 *   <li>errors: missing witness raises {@link WitnessValueMissingError}
 *   <li>wiring: witness bytes appear in the primary unlocking script in
 *       ABI order ({@code _prevOutScript_*} first, then
 *       {@code _serialisedOutputs})
 * </ul>
 *
 * <p>Tests use {@link RunarContract#prepareCall} and inspect the prepared
 * tx hex / unlock script directly — this lets us assert the witness wiring
 * without running the full deploy/call lifecycle through MockProvider.
 */
class IntentWitnessValuesTest {

    private static String paramJson(String name, String type) {
        return "{\"name\":\"" + name + "\",\"type\":\"" + type + "\"}";
    }

    /**
     * Build a stateless artifact with intent-witness params on its single
     * method. Stateless lets us exercise the filter + setter API without
     * needing the full stateful OP_PUSH_TX + funding pipeline.
     */
    private static RunarArtifact makeIntentArtifact(int[] prevOutInputs, boolean serialised) {
        StringBuilder params = new StringBuilder();
        params.append(paramJson("amount", "bigint"));
        for (int i : prevOutInputs) {
            if (params.length() > 0) params.append(",");
            params.append(paramJson("_prevOutScript_" + i, "ByteString"));
        }
        if (serialised) {
            if (params.length() > 0) params.append(",");
            params.append(paramJson("_serialisedOutputs", "ByteString"));
        }
        // Prepend amount comma if witness params followed it
        String paramsJson = paramJson("amount", "bigint");
        StringBuilder more = new StringBuilder();
        for (int i : prevOutInputs) {
            more.append(",").append(paramJson("_prevOutScript_" + i, "ByteString"));
        }
        if (serialised) {
            more.append(",").append(paramJson("_serialisedOutputs", "ByteString"));
        }
        paramsJson = paramsJson + more;

        String json =
            "{"
            + "\"version\":\"runar-v0.1.0\","
            + "\"compilerVersion\":\"0.1.0\","
            + "\"contractName\":\"IntentWitnessTest\","
            + "\"script\":\"51\","
            + "\"asm\":\"\","
            + "\"abi\":{"
                + "\"constructor\":{\"params\":[]},"
                + "\"methods\":[{\"name\":\"move\",\"isPublic\":true,\"params\":["
                + paramsJson + "]}]"
            + "},"
            + "\"buildTimestamp\":\"2026-05-18T00:00:00.000Z\""
            + "}";
        return RunarArtifact.fromJson(json);
    }

    private static RunarContract setupContract(RunarArtifact artifact) {
        UTXO contractUtxo = new UTXO("ab".repeat(32), 0, 10_000L, "51");
        RunarContract contract = new RunarContract(artifact, List.of());
        contract.setCurrentUtxo(contractUtxo);
        return contract;
    }

    // ---------------------------------------------------------------------
    // Filter: arg-count check excludes auto-injected witness params
    // ---------------------------------------------------------------------

    @Test
    void filterExcludesAutoInjectedWitnessParams() {
        RunarArtifact artifact = makeIntentArtifact(new int[]{0, 1}, true);
        RunarContract contract = setupContract(artifact);
        contract.setPrevOutScript(0, "aa");
        contract.setPrevOutScript(1, "bb");
        contract.setSerialisedOutputs("cc");

        // 1 user arg passes (`amount`). Without the filter the SDK would
        // complain "expects 4 args" (amount + 2 prevOutScripts + serialisedOutputs).
        MockProvider provider = new MockProvider();
        PreparedCall pc = contract.prepareCall(
            "move",
            List.of(BigInteger.valueOf(123L)),
            null, provider, new MockSigner()
        );
        // Witness pushes should be in the prepared tx hex.
        String txHex = pc.txHex();
        assertTrue(txHex.contains("01aa"), "prevOut[0] push missing");
        assertTrue(txHex.contains("01bb"), "prevOut[1] push missing");
        assertTrue(txHex.contains("01cc"), "serialised push missing");
    }

    @Test
    void filterStillRejectsRealArgCountMismatches() {
        // The user-facing arg-count check lives in `call()` (the dispatch
        // entry point that splits into callStateless / callWithPushTx /
        // callTerminal). The `prepareCall` API doesn't enforce it
        // because it serves the external-signer flow where the caller
        // explicitly passes one arg slot per method param (sigs as null).
        // Verify the call-entry path rejects mismatched arg counts.
        RunarArtifact artifact = makeIntentArtifact(new int[]{0}, true);
        RunarContract contract = setupContract(artifact);
        // Supply witnesses so we don't hit WitnessValueMissingError first.
        contract.setPrevOutScript(0, "aa");
        contract.setSerialisedOutputs("bb");
        MockProvider provider = new MockProvider();
        MockSigner signer = new MockSigner();
        provider.addUtxo(signer.address(),
            new UTXO("ee".repeat(32), 0, 100_000L,
                ScriptUtils.buildP2PKHScript(signer.address())));

        // Pass 2 args when only `amount` is user-facing
        IllegalArgumentException err = assertThrows(
            IllegalArgumentException.class,
            () -> contract.call(
                "move", List.of(BigInteger.ONE, BigInteger.TWO), null, provider, signer
            )
        );
        assertTrue(err.getMessage().contains("expects 1 user args, got 2"),
            "expected arg count error: " + err.getMessage());
    }

    // ---------------------------------------------------------------------
    // Missing witness ⇒ typed WitnessValueMissingError
    // ---------------------------------------------------------------------

    @Test
    void missingPrevOutScriptRaisesTypedError() {
        RunarArtifact artifact = makeIntentArtifact(new int[]{0}, false);
        RunarContract contract = setupContract(artifact);
        MockProvider provider = new MockProvider();

        WitnessValueMissingError err = assertThrows(
            WitnessValueMissingError.class,
            () -> contract.prepareCall(
                "move", List.of(BigInteger.ONE), null, provider, new MockSigner()
            )
        );
        assertEquals("_prevOutScript_0", err.paramName());
        assertEquals("move", err.methodName());
        assertEquals("IntentWitnessTest", err.contractName());
    }

    @Test
    void missingSerialisedOutputsRaisesTypedError() {
        RunarArtifact artifact = makeIntentArtifact(new int[]{}, true);
        RunarContract contract = setupContract(artifact);
        MockProvider provider = new MockProvider();

        WitnessValueMissingError err = assertThrows(
            WitnessValueMissingError.class,
            () -> contract.prepareCall(
                "move", List.of(BigInteger.ONE), null, provider, new MockSigner()
            )
        );
        assertEquals("_serialisedOutputs", err.paramName());
    }

    // ---------------------------------------------------------------------
    // Wiring: witness bytes appear in the prepared unlocking script
    // ---------------------------------------------------------------------

    @Test
    void appendsMultiplePrevOutScriptsInAbiOrder() {
        RunarArtifact artifact = makeIntentArtifact(new int[]{0, 1}, false);
        RunarContract contract = setupContract(artifact);
        contract.setPrevOutScript(0, "deadbeef");
        contract.setPrevOutScript(1, "cafebabe");
        MockProvider provider = new MockProvider();

        PreparedCall pc = contract.prepareCall(
            "move", List.of(BigInteger.ONE), null, provider, new MockSigner()
        );
        String txHex = pc.txHex();
        // PUSHDATA for 4 bytes = "04" + data
        String push0 = "04" + "deadbeef";
        String push1 = "04" + "cafebabe";
        int idx0 = txHex.indexOf(push0);
        int idx1 = txHex.indexOf(push1);
        assertNotEquals(-1, idx0, "witness 0 push missing in tx hex");
        assertTrue(idx1 > idx0,
            "witness 1 push must follow witness 0 (idx0=" + idx0 + ", idx1=" + idx1 + ")");
    }

    @Test
    void appendsPrevOutThenSerialisedInAbiOrder() {
        RunarArtifact artifact = makeIntentArtifact(new int[]{0}, true);
        RunarContract contract = setupContract(artifact);
        contract.setPrevOutScript(0, "11223344");
        contract.setSerialisedOutputs("55667788");
        MockProvider provider = new MockProvider();

        PreparedCall pc = contract.prepareCall(
            "move", List.of(BigInteger.ONE), null, provider, new MockSigner()
        );
        String txHex = pc.txHex();
        int idxPrev = txHex.indexOf("0411223344");
        int idxSerial = txHex.indexOf("0455667788");
        assertNotEquals(-1, idxPrev, "prevOut push missing");
        assertTrue(idxSerial > idxPrev, "serialised push must follow prevOut push");
    }

    @Test
    void acceptsBytesViaConvenienceSetter() {
        RunarArtifact artifact = makeIntentArtifact(new int[]{0}, false);
        RunarContract contract = setupContract(artifact);
        contract.setPrevOutScript(0, new byte[]{(byte) 0xab, (byte) 0xcd});
        MockProvider provider = new MockProvider();

        PreparedCall pc = contract.prepareCall(
            "move", List.of(BigInteger.ONE), null, provider, new MockSigner()
        );
        // 2-byte push = "02abcd"
        assertTrue(pc.txHex().contains("02abcd"), "2-byte witness push missing");
    }

    @Test
    void rejectsInvalidHex() {
        RunarArtifact artifact = makeIntentArtifact(new int[]{0}, false);
        RunarContract contract = new RunarContract(artifact, List.of());
        assertThrows(IllegalArgumentException.class,
            () -> contract.setPrevOutScript(0, "not-hex!"));
        assertThrows(IllegalArgumentException.class,
            () -> contract.setSerialisedOutputs("abc"));
    }

    private static void assertNotNull(Object value, String message) {
        if (value == null) throw new AssertionError(message);
    }
}

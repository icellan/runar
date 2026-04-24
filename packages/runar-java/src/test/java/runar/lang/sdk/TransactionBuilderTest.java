package runar.lang.sdk;

import java.util.List;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class TransactionBuilderTest {

    private static final String PRIV =
        "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725";

    @Test
    void deployTxParsesBackToMatchingInputsAndOutputs() {
        LocalSigner signer = new LocalSigner(PRIV);
        MockProvider provider = new MockProvider();

        // Fund the signer's address with a single P2PKH UTXO.
        String fundingScript = ScriptUtils.buildP2PKHScript(signer.address());
        UTXO funding = new UTXO("ab".repeat(32), 0, 100_000L, fundingScript);
        provider.addUtxo(signer.address(), funding);

        // Contract locking script: OP_RETURN-preceded data is irrelevant; use a
        // minimal P2PKH-shaped script for structural testing.
        String contractScript = ScriptUtils.buildP2PKHScript("00".repeat(20));

        TransactionBuilder.DeployResult result =
            TransactionBuilder.buildDeployWithLockingScript(
                contractScript, provider, signer, 10_000L, null
            );

        // Structural parse-back.
        RawTx parsed = RawTxParser.parse(result.txHex());
        assertEquals(1, parsed.inputs.size(), "one funding input");
        assertEquals("ab".repeat(32), parsed.inputs.get(0).prevTxid);
        assertEquals(0, parsed.inputs.get(0).prevVout);
        assertEquals(2, parsed.outputs.size(), "contract + change outputs");
        assertEquals(10_000L, parsed.outputs.get(0).satoshis);
        assertEquals(contractScript, parsed.outputs.get(0).scriptPubKeyHex);
        // Change equals totalIn - contract - fee (reasonable upper bound test).
        assertTrue(parsed.outputs.get(1).satoshis > 0 && parsed.outputs.get(1).satoshis < 100_000L);
        // Signed input: scriptSig is <sig><pubkey>.
        assertFalse(parsed.inputs.get(0).scriptSigHex.isEmpty(), "input must be signed");
    }

    @Test
    void deployRejectsInsufficientFunds() {
        LocalSigner signer = new LocalSigner(PRIV);
        MockProvider provider = new MockProvider();

        String fundingScript = ScriptUtils.buildP2PKHScript(signer.address());
        provider.addUtxo(signer.address(), new UTXO("cd".repeat(32), 0, 100L, fundingScript));

        assertThrows(IllegalStateException.class, () ->
            TransactionBuilder.buildDeployWithLockingScript(
                ScriptUtils.buildP2PKHScript("00".repeat(20)),
                provider, signer, 10_000L, null
            )
        );
    }

    @Test
    void deployUsesDefaultChangeAddressFromSignerWhenUnspecified() {
        LocalSigner signer = new LocalSigner(PRIV);
        MockProvider provider = new MockProvider();
        String fundingScript = ScriptUtils.buildP2PKHScript(signer.address());
        provider.addUtxo(signer.address(), new UTXO("ee".repeat(32), 0, 50_000L, fundingScript));

        TransactionBuilder.DeployResult r = TransactionBuilder.buildDeployWithLockingScript(
            ScriptUtils.buildP2PKHScript("11".repeat(20)),
            provider, signer, 1_000L, null
        );
        RawTx parsed = RawTxParser.parse(r.txHex());
        // Change output's script must be P2PKH to signer's own address.
        String expectedChangeScript = ScriptUtils.buildP2PKHScript(signer.address());
        assertEquals(expectedChangeScript, parsed.outputs.get(1).scriptPubKeyHex);
    }
}

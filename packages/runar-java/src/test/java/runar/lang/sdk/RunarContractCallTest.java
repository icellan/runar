package runar.lang.sdk;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Targeted coverage for the three dispatch branches of
 * {@link RunarContract#call(String, java.util.List, java.util.Map, Provider, Signer)}:
 *
 * <ol>
 *   <li><b>callStateless</b> — stateless single-method contracts (P2PKH).</li>
 *   <li><b>callWithPushTx</b> — stateful (or stateless OP_PUSH_TX) contracts
 *       with caller-supplied {@code stateUpdates}.</li>
 *   <li><b>callWithPushTx + AnfInterpreter fallback</b> — stateful contract
 *       with {@code stateUpdates == null}; the SDK runs the embedded
 *       ANF IR through {@link AnfInterpreter#computeNewState} to derive
 *       the post-call state.</li>
 * </ol>
 *
 * <p>These tests use {@link MockProvider} for broadcast and {@link LocalSigner}
 * for real ECDSA signing, so we can verify the contract input's unlocking
 * script ends up containing real (verifiable) signatures rather than the
 * 72-byte zero placeholders the SDK lays down during the first sizing pass.
 */
class RunarContractCallTest {

    private static final String PRIV =
        "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725";

    @Test
    void callDispatchesToCallStatelessForP2pkhAndSignsRealSig() throws Exception {
        // Branch 1: !isStateful && !needsOpPushTx → callStateless().
        // The stateless P2PKH path builds a 1-input call tx, fully
        // consumes the contract UTXO, and signs every Sig placeholder
        // against the contract's BIP-143 sighash. We verify:
        //   - exactly one tx was broadcast
        //   - the resulting tx has a single input + (at most) one P2PKH change output
        //   - the unlocking script's first push is a real DER signature
        //     (not the 72-byte zero placeholder), and verifies under the
        //     signer's pubkey against the BIP-143 sighash of the tx.
        RunarArtifact artifact = loadArtifact("artifacts/basic-p2pkh.runar.json");
        LocalSigner signer = new LocalSigner(PRIV);
        MockProvider provider = new MockProvider();

        String pkhHex = HexFormat.of().formatHex(Hash160.hash160(signer.pubKey()));
        RunarContract contract = new RunarContract(artifact, List.of(pkhHex));
        UTXO contractUtxo = new UTXO("ab".repeat(32), 0, 10_000L, contract.lockingScript());
        contract.setCurrentUtxo(contractUtxo);

        java.util.ArrayList<Object> args = new java.util.ArrayList<>();
        args.add(null); args.add(null);
        RunarContract.CallOutcome out = contract.call(
            "unlock", args, null, provider, signer
        );

        // Provider observed exactly one broadcast.
        assertEquals(1, provider.getBroadcastedTxs().size(),
            "callStateless must broadcast the rebuilt tx exactly once");
        assertEquals(out.rawTxHex(), provider.getBroadcastedTxs().get(0));
        assertNotNull(out.txid());
        assertNull(out.nextContractUtxo(),
            "stateless terminal call: no continuation UTXO");

        // Tx shape: 1 input (the contract), 0-or-1 outputs (P2PKH change).
        RawTx tx = RawTxParser.parse(out.rawTxHex());
        assertEquals(1, tx.inputs.size(), "stateless P2PKH path: single contract input");
        assertTrue(tx.outputs.size() <= 1,
            "stateless P2PKH path: at most one change output, got " + tx.outputs.size());

        // The unlocking script must NOT contain the 72-byte zero placeholder
        // (if it did, we'd be on the prepareCall path or the second-pass
        // signing branch never ran). Likewise, the first push in the unlock
        // is a real DER signature.
        String unlockHex = tx.inputs.get(0).scriptSigHex;
        assertFalse(unlockHex.contains("00".repeat(72)),
            "real signature must replace placeholder; unlock=" + unlockHex);

        // First push: a real DER signature (LocalSigner emits low-S DER which
        // BouncyCastle packs into 70..72 bytes; with the appended
        // SIGHASH_ALL_FORKID flag the push length is 71..73). Verify whatever
        // opcode it is decodes a push that begins with the DER 0x30 tag and
        // ends with the 0x41 sighash flag byte.
        ScriptUtils.DecodedPush sigPush = ScriptUtils.decodePushData(unlockHex, 0);
        assertNotNull(sigPush, "unlock must start with a sig push");
        assertTrue(sigPush.dataHex().startsWith("30"),
            "first push is a DER signature (starts with 0x30); got " + sigPush.dataHex());
        assertTrue(sigPush.dataHex().endsWith("41"),
            "DER sig must terminate with SIGHASH_ALL|FORKID byte; got " + sigPush.dataHex());

        // Strip the flag byte and verify the DER signature against the
        // BIP-143 sighash of this tx, under the signer's pubkey. This
        // pins the assertion to the callStateless path — only that path
        // builds and signs against `tx.sighashBIP143(0, scriptHex, sats, ...)`
        // and then re-broadcasts the signed tx.
        byte[] der = HexFormat.of().parseHex(
            sigPush.dataHex().substring(0, sigPush.dataHex().length() - 2)
        );
        byte[] sighash = tx.sighashBIP143(
            0, contractUtxo.scriptHex(), contractUtxo.satoshis(), RawTx.SIGHASH_ALL_FORKID
        );
        assertTrue(verifyDerSig(der, sighash, signer.pubKey()),
            "stateless-call signature must verify under signer's pubkey "
                + "against the tx's BIP-143 sighash");
    }

    @Test
    void callDispatchesToCallWithPushTxForStatefulContract() throws Exception {
        // Branch 2: isStateful → callWithPushTx() with explicit stateUpdates.
        // The stateful flow:
        //   - rebuilds a continuation output with the new state appended
        //     after OP_RETURN
        //   - borrows P2PKH UTXOs from the signer to pay the fee
        //   - lays out a 2-pass tx (placeholder unlock → real unlock with
        //     OP_PUSH_TX sig + preimage spliced in)
        // We assert: the broadcast shape (>= 2 inputs, contract continuation
        // at output 0), the new currentUtxo points to that continuation, and
        // the continuation's locking script has the spec-compliant
        // codePart + 0x6a (OP_RETURN) + state-encoded count=1 layout.
        RunarArtifact artifact = loadArtifact("artifacts/stateful-counter.runar.json");
        LocalSigner signer = new LocalSigner(PRIV);
        MockProvider provider = new MockProvider();

        // Seed the signer's address with a single funding UTXO. The
        // contract continuation reuses the contract's own satoshis, so the
        // funder UTXO only needs to cover the fee.
        provider.addUtxo(signer.address(),
            new UTXO("ff".repeat(32), 7, 200_000L,
                ScriptUtils.buildP2PKHScript(signer.address())));

        RunarContract contract = new RunarContract(
            artifact, List.of(BigInteger.ZERO)
        );
        UTXO contractUtxo = new UTXO("cc".repeat(32), 0, 5_000L, contract.lockingScript());
        contract.setCurrentUtxo(contractUtxo);

        // Caller-supplied stateUpdates win over the AnfInterpreter
        // fallback. Set count=1 explicitly.
        Map<String, Object> updates = new HashMap<>();
        updates.put("count", BigInteger.ONE);

        RunarContract.CallOutcome out = contract.call(
            "increment", List.of(), updates, provider, signer
        );

        assertEquals(1, provider.getBroadcastedTxs().size(),
            "callWithPushTx must broadcast exactly once");
        assertNotNull(out.txid());
        assertNotNull(out.nextContractUtxo(),
            "stateful contract: continuation UTXO must be returned");
        assertSame(contract.currentUtxo(), out.nextContractUtxo(),
            "currentUtxo must track the new continuation");
        assertEquals(out.txid(), out.nextContractUtxo().txid());
        assertEquals(0, out.nextContractUtxo().outputIndex());
        assertEquals(contractUtxo.satoshis(), out.nextContractUtxo().satoshis(),
            "stateful continuation reuses the contract's satoshis");

        // The continuation's locking script has the structure:
        //   <codePart> 6a <stateHex>
        // where codePart is everything before the last OP_RETURN of the
        // current contract script, and stateHex is the serialized count=1.
        String codePart = ContractScript.extractCodePart(contractUtxo.scriptHex());
        String expectedState = StateSerializer.serialize(
            artifact.stateFields(), Map.of("count", BigInteger.ONE)
        );
        String expectedContinuation = codePart + "6a" + expectedState;
        assertEquals(expectedContinuation, out.nextContractUtxo().scriptHex(),
            "continuation script must be codePart || OP_RETURN || state(count=1)");

        // Tx layout: contract input + at least one funding input.
        RawTx tx = RawTxParser.parse(out.rawTxHex());
        assertTrue(tx.inputs.size() >= 2,
            "callWithPushTx layout requires contract input + funder; got "
                + tx.inputs.size());
        assertEquals(contractUtxo.txid(), tx.inputs.get(0).prevTxid,
            "input 0 is the contract being spent");
        assertTrue(tx.outputs.size() >= 1, "at least the continuation output");
        assertEquals(expectedContinuation, tx.outputs.get(0).scriptPubKeyHex,
            "output 0 is the contract continuation");

        // The contract input's unlocking script ends with a real OP_PUSH_TX
        // signature + a real preimage push — neither is the all-zero
        // placeholder produced by the first-pass layout.
        String unlockHex = tx.inputs.get(0).scriptSigHex;
        assertFalse(unlockHex.contains("00".repeat(181)),
            "preimage placeholder must be replaced; unlock=" + unlockHex);
        assertFalse(unlockHex.contains("00".repeat(72)),
            "OP_PUSH_TX sig placeholder must be replaced; unlock=" + unlockHex);
    }

    @Test
    void callFallsBackToAnfInterpreterWhenStateUpdatesNull() throws Exception {
        // Branch 3: isStateful && stateUpdates == null && artifact.anf() != null
        // → AnfInterpreter.computeNewState fills in the new state. Mirrors
        // the integration test path
        // (integration/java/.../CounterIntegrationTest#incrementOnce).
        RunarArtifact artifact = loadArtifact("artifacts/stateful-counter.runar.json");
        assertNotNull(artifact.anf(),
            "fixture pre-condition: stateful-counter artifact must carry an ANF subtree");

        LocalSigner signer = new LocalSigner(PRIV);
        MockProvider provider = new MockProvider();
        provider.addUtxo(signer.address(),
            new UTXO("ee".repeat(32), 3, 200_000L,
                ScriptUtils.buildP2PKHScript(signer.address())));

        // Seed the contract with count=5; increment must move it to 6 via
        // the interpreter, not via caller-supplied updates.
        RunarContract contract = new RunarContract(
            artifact, List.of(BigInteger.valueOf(5))
        );
        assertEquals(BigInteger.valueOf(5), contract.state().get("count"),
            "constructor must seed count=5 from the constructor arg");
        UTXO contractUtxo = new UTXO("dd".repeat(32), 0, 6_000L, contract.lockingScript());
        contract.setCurrentUtxo(contractUtxo);

        // Independent reference: what the interpreter would compute.
        Map<String, Object> referenceState = AnfInterpreter.computeNewState(
            artifact.anf(),
            "increment",
            Map.of("count", BigInteger.valueOf(5)),
            Map.of(),
            List.of(BigInteger.valueOf(5))
        );
        assertEquals(BigInteger.valueOf(6), referenceState.get("count"),
            "reference: AnfInterpreter increments 5 -> 6");

        // Now run call() with stateUpdates=null and assert the SDK arrived
        // at the same post-state (i.e., it really invoked the interpreter
        // instead of leaving state unchanged or asking the caller).
        RunarContract.CallOutcome out = contract.call(
            "increment", List.of(), /*stateUpdates*/ null, provider, signer
        );
        assertNotNull(out.txid());
        assertEquals(BigInteger.valueOf(6), contract.state().get("count"),
            "AnfInterpreter fallback must drive count from 5 to 6");

        // The continuation locking script must encode count=6 — the only
        // way that can happen end-to-end is if the interpreter populated
        // state before the continuation was built.
        String codePart = ContractScript.extractCodePart(contractUtxo.scriptHex());
        String expectedState = StateSerializer.serialize(
            artifact.stateFields(), Map.of("count", BigInteger.valueOf(6))
        );
        assertEquals(codePart + "6a" + expectedState,
            contract.currentUtxo().scriptHex(),
            "continuation script must reflect the interpreter-computed count=6");
    }

    @Test
    void callWithOptionsTerminalOutputsBuildsExactOutputsAndClearsUtxo() throws Exception {
        // Branch 4: callWithOptions(... terminalOutputs ...) → callTerminal().
        // Verifies the new terminal-output flow: caller-supplied outputs
        // replace the auto-computed change/continuation entirely, the
        // contract UTXO is fully spent, and currentUtxo is cleared.
        RunarArtifact artifact = loadArtifact("artifacts/basic-p2pkh.runar.json");
        LocalSigner signer = new LocalSigner(PRIV);
        MockProvider provider = new MockProvider();

        String pkhHex = HexFormat.of().formatHex(Hash160.hash160(signer.pubKey()));
        RunarContract contract = new RunarContract(artifact, List.of(pkhHex));
        UTXO contractUtxo = new UTXO("ee".repeat(32), 0, 10_000L, contract.lockingScript());
        contract.setCurrentUtxo(contractUtxo);

        // Two terminal outputs: 4000 + 5000 sats. The remaining 1000 sats
        // becomes the (implicit) miner fee.
        String destPkh = "aa".repeat(20);
        String destScript = "76a914" + destPkh + "88ac";
        java.util.List<runar.lang.sdk.CallOptions.TerminalOutput> outs = java.util.List.of(
            new runar.lang.sdk.CallOptions.TerminalOutput(
                java.math.BigInteger.valueOf(4000), null, destScript),
            new runar.lang.sdk.CallOptions.TerminalOutput(
                java.math.BigInteger.valueOf(5000), null, "51")
        );

        java.util.ArrayList<Object> args = new java.util.ArrayList<>();
        args.add(null); args.add(null); // sig + pubKey auto-resolved
        RunarContract.CallOutcome out = contract.callWithOptions(
            "unlock", args, runar.lang.sdk.CallOptions.terminal(outs), provider, signer
        );

        assertEquals(1, provider.getBroadcastedTxs().size());
        assertNotNull(out.txid());
        assertNull(out.nextContractUtxo(),
            "terminal call must report no continuation UTXO");
        assertNull(contract.currentUtxo(),
            "terminal call must clear currentUtxo (contract fully spent)");

        RawTx tx = RawTxParser.parse(out.rawTxHex());
        assertEquals(1, tx.inputs.size(),
            "no funding UTXOs supplied → only the contract input");
        assertEquals(2, tx.outputs.size(),
            "outputs must be exactly the two terminal outputs (no change)");
        assertEquals(4000L, tx.outputs.get(0).satoshis);
        assertEquals(destScript, tx.outputs.get(0).scriptPubKeyHex);
        assertEquals(5000L, tx.outputs.get(1).satoshis);
        assertEquals("51", tx.outputs.get(1).scriptPubKeyHex);
    }

    @Test
    void terminalOutputResolvesAddressIntoP2pkhScript() {
        // When callers pass a TerminalOutput with `address` instead of
        // `scriptHex`, the SDK must build a standard P2PKH locking script.
        runar.lang.sdk.CallOptions.TerminalOutput byHex =
            new runar.lang.sdk.CallOptions.TerminalOutput(
                java.math.BigInteger.valueOf(1000), null,
                "76a914" + "11".repeat(20) + "88ac");
        assertEquals("76a914" + "11".repeat(20) + "88ac", byHex.resolveScriptHex());

        runar.lang.sdk.CallOptions.TerminalOutput byPkhHex =
            new runar.lang.sdk.CallOptions.TerminalOutput(
                java.math.BigInteger.valueOf(2000),
                "22".repeat(20), null); // 40-char hex pkh
        assertEquals("76a914" + "22".repeat(20) + "88ac", byPkhHex.resolveScriptHex());
    }

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------

    private static RunarArtifact loadArtifact(String classpathRel) throws Exception {
        Path resource = Path.of("src/test/resources/" + classpathRel);
        if (!Files.exists(resource)) {
            try (var in = RunarContractCallTest.class.getClassLoader().getResourceAsStream(classpathRel)) {
                if (in == null) throw new IllegalStateException("missing fixture " + classpathRel);
                return RunarArtifact.fromJson(new String(in.readAllBytes()));
            }
        }
        return RunarArtifact.fromJson(Files.readString(resource));
    }

    /** ECDSA verify helper: returns {@code true} if {@code der} verifies under {@code pubKey} against {@code msg}. */
    private static boolean verifyDerSig(byte[] der, byte[] msg, byte[] pubKey) throws Exception {
        try (ASN1InputStream in = new ASN1InputStream(der)) {
            ASN1Sequence seq = (ASN1Sequence) in.readObject();
            BigInteger r = ((ASN1Integer) seq.getObjectAt(0)).getValue();
            BigInteger s = ((ASN1Integer) seq.getObjectAt(1)).getValue();
            ECPoint pub = LocalSigner.DOMAIN.getCurve().decodePoint(pubKey);
            ECDSASigner verifier = new ECDSASigner();
            verifier.init(false, new ECPublicKeyParameters(pub, LocalSigner.DOMAIN));
            return verifier.verifySignature(msg, r, s);
        }
    }
}

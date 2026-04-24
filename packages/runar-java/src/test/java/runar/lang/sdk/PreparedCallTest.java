package runar.lang.sdk;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PreparedCallTest {

    private static final String PRIV =
        "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725";

    // ------------------------------------------------------------------
    // Round-trip: prepare → external sign → finalize → broadcast
    // ------------------------------------------------------------------

    @Test
    void preparedCallRoundTripsSinglePartyFlow() throws Exception {
        LocalSigner signer = new LocalSigner(PRIV);
        MockProvider provider = new MockProvider();

        RunarArtifact artifact = loadArtifact("artifacts/basic-p2pkh.runar.json");

        // Construct the contract with the signer's own pubkey hash so
        // the on-chain unlock would verify against the signer's key.
        String pkhHex = HexFormat.of().formatHex(Hash160.hash160(signer.pubKey()));
        RunarContract contract = new RunarContract(artifact, List.of(pkhHex));

        // Seed the contract as already deployed at a known outpoint.
        UTXO contractUtxo = new UTXO(
            "ab".repeat(32), 0, 10_000L, contract.lockingScript()
        );
        contract.setCurrentUtxo(contractUtxo);

        // Prepare: pass nulls for Sig + PubKey — the SDK fills in the
        // pubkey (from the provided signer, so the unlocking script has
        // a valid pubkey) and a 72-byte Sig placeholder.
        List<Object> args = new ArrayList<>();
        args.add(null); // sig
        args.add(null); // pubKey
        PreparedCall prepared = contract.prepareCall(
            "unlock", args, null, provider, signer
        );

        assertEquals(1, prepared.sigIndices().size(), "one Sig placeholder expected");
        assertEquals(0, (int) prepared.sigIndices().get(0));
        assertEquals(1, prepared.sighashes().size());
        assertEquals(32, prepared.sighashes().get(0).length);
        assertFalse(prepared.isStateful());
        assertNotNull(prepared.txHex());

        // Sanity: the sighash computed on the prepared tx matches what
        // RawTx.sighashBIP143 would produce on the same inputs.
        RawTx parsed = RawTxParser.parse(prepared.txHex());
        byte[] expected = parsed.sighashBIP143(
            0, contractUtxo.scriptHex(), contractUtxo.satoshis(),
            RawTx.SIGHASH_ALL_FORKID
        );
        assertArrayEquals(expected, prepared.sighashes().get(0));

        // External sign step (simulated).
        byte[] der = signer.sign(prepared.sighashes().get(0), null);

        // Verify the signature with BouncyCastle.
        BigInteger[] rs = decodeDer(der);
        ECPoint pub = LocalSigner.DOMAIN.getCurve().decodePoint(signer.pubKey());
        ECDSASigner verifier = new ECDSASigner();
        verifier.init(false, new ECPublicKeyParameters(pub, LocalSigner.DOMAIN));
        assertTrue(
            verifier.verifySignature(prepared.sighashes().get(0), rs[0], rs[1]),
            "external signature must verify under the signer's pubkey"
        );

        // Finalize.
        RunarContract.CallOutcome outcome = contract.finalizeCall(
            prepared, List.of(der), provider
        );

        assertNotNull(outcome.txid());
        assertNotNull(outcome.rawTxHex());
        // Broadcast happened exactly once.
        assertEquals(1, provider.getBroadcastedTxs().size());
        assertEquals(outcome.rawTxHex(), provider.getBroadcastedTxs().get(0));

        // The final tx must contain the real sig, not the placeholder.
        assertFalse(outcome.rawTxHex().contains("00".repeat(72)),
            "placeholder must be replaced in the final tx");
    }

    // ------------------------------------------------------------------
    // Wrong-shape signature is rejected at finalize time
    // ------------------------------------------------------------------

    @Test
    void finalizeRejectsNonDerSignature() {
        LocalSigner signer = new LocalSigner(PRIV);
        MockProvider provider = new MockProvider();
        RunarArtifact artifact = loadArtifact("artifacts/basic-p2pkh.runar.json");
        RunarContract contract = new RunarContract(
            artifact,
            List.of(HexFormat.of().formatHex(Hash160.hash160(signer.pubKey())))
        );
        contract.setCurrentUtxo(new UTXO("ab".repeat(32), 0, 10_000L, contract.lockingScript()));

        PreparedCall prepared = contract.prepareCall(
            "unlock", Arrays.asList(null, null), null, provider, signer
        );

        // Garbage bytes — starts with 0x00, not DER 0x30.
        byte[] bogus = new byte[] { 0x00, 0x11, 0x22 };
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
            () -> contract.finalizeCall(prepared, List.of(bogus), provider));
        assertTrue(ex.getMessage().contains("DER"), ex.getMessage());
    }

    @Test
    void finalizeRejectsSignatureCountMismatch() {
        LocalSigner signer = new LocalSigner(PRIV);
        MockProvider provider = new MockProvider();
        RunarArtifact artifact = loadArtifact("artifacts/basic-p2pkh.runar.json");
        RunarContract contract = new RunarContract(
            artifact,
            List.of(HexFormat.of().formatHex(Hash160.hash160(signer.pubKey())))
        );
        contract.setCurrentUtxo(new UTXO("ab".repeat(32), 0, 10_000L, contract.lockingScript()));

        PreparedCall prepared = contract.prepareCall(
            "unlock", Arrays.asList(null, null), null, provider, signer
        );

        assertThrows(IllegalArgumentException.class,
            () -> contract.finalizeCall(prepared, Collections.emptyList(), provider));
        assertThrows(IllegalArgumentException.class,
            () -> contract.finalizeCall(prepared, null, provider));
    }

    // ------------------------------------------------------------------
    // Multi-party flow: two Sig params, two external signatures
    // ------------------------------------------------------------------

    @Test
    void multiPartyPreparedCallAcceptsTwoSignaturesInOrder() {
        LocalSigner alice = new LocalSigner(PRIV);
        LocalSigner bob = LocalSigner.random(new java.security.SecureRandom());

        MockProvider provider = new MockProvider();

        // Hand-craft a two-Sig stateless artifact: the contract takes
        // two Sig params (alice, bob) — the actual locking-script logic
        // doesn't matter for this test; we only need prepareCall to
        // detect *two* Sig placeholders and emit two sighashes.
        String json = """
            {
              "version": "runar-v0.1.0",
              "compilerVersion": "0.1.0",
              "contractName": "TwoOfTwo",
              "abi": {
                "constructor": { "params": [] },
                "methods": [
                  {
                    "name": "unlock",
                    "params": [
                      {"name": "aliceSig", "type": "Sig"},
                      {"name": "bobSig",   "type": "Sig"}
                    ],
                    "isPublic": true
                  }
                ]
              },
              "script": "51",
              "asm": "OP_1",
              "buildTimestamp": "2026-01-01T00:00:00Z"
            }
            """;
        RunarArtifact artifact = RunarArtifact.fromJson(json);
        RunarContract contract = new RunarContract(artifact, List.of());
        contract.setCurrentUtxo(new UTXO("cd".repeat(32), 0, 20_000L, contract.lockingScript()));

        List<Object> args = Arrays.asList(null, null);
        PreparedCall prepared = contract.prepareCall(
            "unlock", args, null, provider, alice
        );

        assertEquals(2, prepared.sigIndices().size(), "two Sig placeholders expected");
        assertEquals(List.of(0, 1), prepared.sigIndices());
        assertEquals(2, prepared.sighashes().size());

        // BIP-143 does not cover scriptSig → both sighashes are identical
        // for the same input. Each signer can sign independently.
        assertArrayEquals(prepared.sighashes().get(0), prepared.sighashes().get(1));

        byte[] aliceSig = alice.sign(prepared.sighashes().get(0), null);
        byte[] bobSig   = bob.sign(prepared.sighashes().get(1), null);

        RunarContract.CallOutcome outcome = contract.finalizeCall(
            prepared, List.of(aliceSig, bobSig), provider
        );

        assertNotNull(outcome.txid());
        assertEquals(1, provider.getBroadcastedTxs().size());

        // Both signatures must appear in the final unlocking script, in
        // order (alice first, bob second) with the SIGHASH_ALL|FORKID
        // flag byte (0x41) appended.
        String aliceHex = HexFormat.of().formatHex(aliceSig) + "41";
        String bobHex   = HexFormat.of().formatHex(bobSig) + "41";
        String raw = outcome.rawTxHex();
        int alicePos = raw.indexOf(aliceHex);
        int bobPos   = raw.indexOf(bobHex);
        assertTrue(alicePos >= 0, "alice sig missing from final tx");
        assertTrue(bobPos   >  alicePos, "bob sig must follow alice in unlocking script");
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private static BigInteger[] decodeDer(byte[] der) throws Exception {
        try (ASN1InputStream in = new ASN1InputStream(der)) {
            ASN1Sequence seq = (ASN1Sequence) in.readObject();
            BigInteger r = ((ASN1Integer) seq.getObjectAt(0)).getValue();
            BigInteger s = ((ASN1Integer) seq.getObjectAt(1)).getValue();
            return new BigInteger[] { r, s };
        }
    }

    static RunarArtifact loadArtifact(String relative) {
        try {
            String repoRoot = System.getProperty("runar.repo.root");
            if (repoRoot != null) {
                Path p = Path.of(repoRoot, relative);
                if (Files.exists(p)) return RunarArtifact.fromJson(Files.readString(p));
            }
            Path cwd = Path.of("").toAbsolutePath();
            Path p = cwd;
            for (int i = 0; i < 8; i++) {
                Path candidate = p.resolve(relative);
                if (Files.exists(candidate)) return RunarArtifact.fromJson(Files.readString(candidate));
                Path parent = p.getParent();
                if (parent == null) break;
                p = parent;
            }
            throw new IllegalStateException("fixture not found: " + relative + " (cwd=" + cwd + ", runar.repo.root=" + repoRoot + ")");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}

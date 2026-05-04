package runar.lang.sdk;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link AnfInterpreter#executeOnChainAuthoritative} — the third
 * execution mode that runs strict assert enforcement PLUS real ECDSA /
 * SHA-256 preimage verification against a caller-supplied sighash.
 *
 * <p>Mirrors {@code packages/runar-sdk/src/__tests__/anf-interpreter-real-crypto.spec.ts}
 * and the equivalent Zig tests in {@code packages/runar-zig/src/sdk_anf_interpreter.zig}.
 */
class AnfInterpreterRealCryptoTest {

    private static final HexFormat HEX = HexFormat.of();

    // Deterministic test private key — fixture only, never use on-chain.
    private static final String TEST_PRIV_HEX =
        "aa11bb22cc33dd44ee55ff667788990011223344556677889900aabbccddeeff";

    private static byte[] sha256(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

    private static byte[] hash256(byte[] data) throws Exception {
        return sha256(sha256(data));
    }

    private static byte[] sighashFor(String message) throws Exception {
        return sha256(message.getBytes("UTF-8"));
    }

    /** Sign a 32-byte digest with BouncyCastle's secp256k1 + RFC 6979 + low-S. */
    private static byte[] signDigest(BigInteger priv, byte[] digest) throws Exception {
        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
        signer.init(true, new ECPrivateKeyParameters(priv, LocalSigner.DOMAIN));
        BigInteger[] rs = signer.generateSignature(digest);
        BigInteger r = rs[0];
        BigInteger s = rs[1];
        BigInteger halfN = LocalSigner.DOMAIN.getN().shiftRight(1);
        if (s.compareTo(halfN) > 0) s = LocalSigner.DOMAIN.getN().subtract(s);
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(r));
        v.add(new ASN1Integer(s));
        return new DERSequence(v).getEncoded("DER");
    }

    private static String pubKeyHex(BigInteger priv) {
        ECPoint p = LocalSigner.DOMAIN.getG().multiply(priv).normalize();
        return HEX.formatHex(p.getEncoded(true));
    }

    /** P2PKH-like Guard{ value }: unlock(sig, pk) asserts checkSig, sets value=1. */
    private static Map<String, Object> sigGuardAnf() {
        return Map.of(
            "contractName", "Guard",
            "properties", List.of(Map.of("name", "value", "type", "bigint", "readonly", false)),
            "methods", List.of(Map.of(
                "name", "unlock",
                "isPublic", true,
                "params", List.of(
                    Map.of("name", "sig", "type", "Sig"),
                    Map.of("name", "pk",  "type", "PubKey")
                ),
                "body", List.of(
                    Map.of("name", "sigArg", "value", Map.of("kind", "load_param", "name", "sig")),
                    Map.of("name", "pkArg",  "value", Map.of("kind", "load_param", "name", "pk")),
                    Map.of("name", "sigOk",  "value", Map.of("kind", "call", "func", "checkSig",
                        "args", List.of("sigArg", "pkArg"))),
                    Map.of("name", "assertSig", "value", Map.of("kind", "assert", "value", "sigOk")),
                    Map.of("name", "one", "value", Map.of("kind", "load_const", "value", BigInteger.ONE)),
                    Map.of("name", "upd", "value", Map.of("kind", "update_prop",
                        "name", "value", "value", "one"))
                )
            ))
        );
    }

    /** PreimageGuard{ value }: unlock(preimage) asserts checkPreimage, sets value=1. */
    private static Map<String, Object> preimageGuardAnf() {
        return Map.of(
            "contractName", "PreimageGuard",
            "properties", List.of(Map.of("name", "value", "type", "bigint", "readonly", false)),
            "methods", List.of(Map.of(
                "name", "unlock",
                "isPublic", true,
                "params", List.of(Map.of("name", "preimage", "type", "SigHashPreimage")),
                "body", List.of(
                    Map.of("name", "pre",   "value", Map.of("kind", "load_param", "name", "preimage")),
                    Map.of("name", "preOk", "value", Map.of("kind", "call", "func", "checkPreimage",
                        "args", List.of("pre"))),
                    Map.of("name", "assertPre", "value", Map.of("kind", "assert", "value", "preOk")),
                    Map.of("name", "one", "value", Map.of("kind", "load_const", "value", BigInteger.ONE)),
                    Map.of("name", "upd", "value", Map.of("kind", "update_prop",
                        "name", "value", "value", "one"))
                )
            ))
        );
    }

    /** MultisigGuard{ value }: unlock(sigs, pks) asserts checkMultiSig. */
    private static Map<String, Object> multisigGuardAnf() {
        return Map.of(
            "contractName", "MultisigGuard",
            "properties", List.of(Map.of("name", "value", "type", "bigint", "readonly", false)),
            "methods", List.of(Map.of(
                "name", "unlock",
                "isPublic", true,
                "params", List.of(
                    Map.of("name", "sigs", "type", "Sig[]"),
                    Map.of("name", "pks",  "type", "PubKey[]")
                ),
                "body", List.of(
                    Map.of("name", "sigsArg", "value", Map.of("kind", "load_param", "name", "sigs")),
                    Map.of("name", "pksArg",  "value", Map.of("kind", "load_param", "name", "pks")),
                    Map.of("name", "msigOk",  "value", Map.of("kind", "call",
                        "func", "checkMultiSig", "args", List.of("sigsArg", "pksArg"))),
                    Map.of("name", "assertMsig", "value", Map.of("kind", "assert", "value", "msigOk")),
                    Map.of("name", "one", "value", Map.of("kind", "load_const", "value", BigInteger.ONE)),
                    Map.of("name", "upd", "value", Map.of("kind", "update_prop",
                        "name", "value", "value", "one"))
                )
            ))
        );
    }

    // ---- checkSig --------------------------------------------------------

    @Test
    void checkSigPassesWithRealSignature() throws Exception {
        BigInteger priv = new BigInteger(1, HEX.parseHex(TEST_PRIV_HEX));
        byte[] sighash = sighashFor("runar-java-anf-real-crypto-test");
        byte[] sig = signDigest(priv, sighash);
        AnfInterpreter.OnChainCryptoContext ctx =
            new AnfInterpreter.OnChainCryptoContext(sighash);

        AnfInterpreter.ExecutionResult result = AnfInterpreter.executeOnChainAuthoritative(
            sigGuardAnf(), "unlock",
            Map.of("value", BigInteger.ZERO),
            Map.of("sig", HEX.formatHex(sig), "pk", pubKeyHex(priv)),
            List.of(),
            ctx
        );
        assertEquals(BigInteger.ONE, result.newState.get("value"));
    }

    @Test
    void checkSigFailsWithCorruptedSignature() throws Exception {
        BigInteger priv = new BigInteger(1, HEX.parseHex(TEST_PRIV_HEX));
        byte[] sighash = sighashFor("runar-java-anf-real-crypto-test");
        byte[] sig = signDigest(priv, sighash);
        sig[sig.length - 1] ^= (byte) 0xff;  // corrupt last byte
        AnfInterpreter.OnChainCryptoContext ctx =
            new AnfInterpreter.OnChainCryptoContext(sighash);

        assertThrows(AnfInterpreter.AssertionFailureException.class, () ->
            AnfInterpreter.executeOnChainAuthoritative(
                sigGuardAnf(), "unlock",
                Map.of("value", BigInteger.ZERO),
                Map.of("sig", HEX.formatHex(sig), "pk", pubKeyHex(priv)),
                List.of(),
                ctx
            )
        );
    }

    @Test
    void checkSigFailsWithWrongSighash() throws Exception {
        BigInteger priv = new BigInteger(1, HEX.parseHex(TEST_PRIV_HEX));
        byte[] sighashSigned = sighashFor("the-message-actually-signed");
        byte[] sig = signDigest(priv, sighashSigned);
        byte[] sighashClaimed = sighashFor("a-different-message");
        AnfInterpreter.OnChainCryptoContext ctx =
            new AnfInterpreter.OnChainCryptoContext(sighashClaimed);

        assertThrows(AnfInterpreter.AssertionFailureException.class, () ->
            AnfInterpreter.executeOnChainAuthoritative(
                sigGuardAnf(), "unlock",
                Map.of("value", BigInteger.ZERO),
                Map.of("sig", HEX.formatHex(sig), "pk", pubKeyHex(priv)),
                List.of(),
                ctx
            )
        );
    }

    // ---- checkPreimage ---------------------------------------------------

    @Test
    void checkPreimagePassesWhenPreimageHashesToSighash() throws Exception {
        byte[] preimage = HEX.parseHex("deadbeefcafebabef00d");
        byte[] sighash = hash256(preimage);
        AnfInterpreter.OnChainCryptoContext ctx =
            new AnfInterpreter.OnChainCryptoContext(sighash);

        AnfInterpreter.ExecutionResult result = AnfInterpreter.executeOnChainAuthoritative(
            preimageGuardAnf(), "unlock",
            Map.of("value", BigInteger.ZERO),
            Map.of("preimage", HEX.formatHex(preimage)),
            List.of(),
            ctx
        );
        assertEquals(BigInteger.ONE, result.newState.get("value"));
    }

    @Test
    void checkPreimageFailsWithWrongPreimage() throws Exception {
        byte[] correctPreimage = HEX.parseHex("deadbeef");
        byte[] sighash = hash256(correctPreimage);
        byte[] wrongPreimage = HEX.parseHex("01020304");
        AnfInterpreter.OnChainCryptoContext ctx =
            new AnfInterpreter.OnChainCryptoContext(sighash);

        assertThrows(AnfInterpreter.AssertionFailureException.class, () ->
            AnfInterpreter.executeOnChainAuthoritative(
                preimageGuardAnf(), "unlock",
                Map.of("value", BigInteger.ZERO),
                Map.of("preimage", HEX.formatHex(wrongPreimage)),
                List.of(),
                ctx
            )
        );
    }

    // ---- checkMultiSig ---------------------------------------------------

    @Test
    void checkMultiSigPassesWith2Of2() throws Exception {
        BigInteger priv1 = new BigInteger(1, HEX.parseHex(TEST_PRIV_HEX));
        BigInteger priv2 = new BigInteger(1, HEX.parseHex(repeat("22", 32)));
        byte[] sighash = sighashFor("runar-java-multisig-test");
        byte[] sig1 = signDigest(priv1, sighash);
        byte[] sig2 = signDigest(priv2, sighash);

        AnfInterpreter.OnChainCryptoContext ctx =
            new AnfInterpreter.OnChainCryptoContext(sighash);

        AnfInterpreter.ExecutionResult result = AnfInterpreter.executeOnChainAuthoritative(
            multisigGuardAnf(), "unlock",
            Map.of("value", BigInteger.ZERO),
            Map.of(
                "sigs", List.of(HEX.formatHex(sig1), HEX.formatHex(sig2)),
                "pks",  List.of(pubKeyHex(priv1), pubKeyHex(priv2))
            ),
            List.of(),
            ctx
        );
        assertEquals(BigInteger.ONE, result.newState.get("value"));
    }

    @Test
    void checkMultiSigFailsWithCorruptedSig() throws Exception {
        BigInteger priv1 = new BigInteger(1, HEX.parseHex(TEST_PRIV_HEX));
        BigInteger priv2 = new BigInteger(1, HEX.parseHex(repeat("22", 32)));
        byte[] sighash = sighashFor("runar-java-multisig-test");
        byte[] sig1 = signDigest(priv1, sighash);
        byte[] sig2 = signDigest(priv2, sighash);
        sig2[sig2.length - 1] ^= (byte) 0xff;

        AnfInterpreter.OnChainCryptoContext ctx =
            new AnfInterpreter.OnChainCryptoContext(sighash);

        assertThrows(AnfInterpreter.AssertionFailureException.class, () ->
            AnfInterpreter.executeOnChainAuthoritative(
                multisigGuardAnf(), "unlock",
                Map.of("value", BigInteger.ZERO),
                Map.of(
                    "sigs", List.of(HEX.formatHex(sig1), HEX.formatHex(sig2)),
                    "pks",  List.of(pubKeyHex(priv1), pubKeyHex(priv2))
                ),
                List.of(),
                ctx
            )
        );
    }

    // ---- Mode parity (no regression in lenient/strict mocks) ------------

    @Test
    void lenientModeStillMocksCheckSig() {
        // Garbage sig + pk passes lenient because asserts are skipped AND
        // checkSig is mocked-true (not relevant in lenient since asserts
        // skipped, but documented behaviour).
        Map<String, Object> result = AnfInterpreter.computeNewState(
            sigGuardAnf(), "unlock",
            Map.of("value", BigInteger.ZERO),
            Map.of("sig", "deadbeef", "pk", "cafebabe"),
            List.of()
        );
        assertEquals(BigInteger.ONE, result.get("value"));
    }

    @Test
    void strictModeStillMocksCheckSig() {
        // Strict enforces the assert but checkSig still mock-returns true,
        // so garbage sig + pk passes.
        AnfInterpreter.ExecutionResult result = AnfInterpreter.executeStrict(
            sigGuardAnf(), "unlock",
            Map.of("value", BigInteger.ZERO),
            Map.of("sig", "deadbeef", "pk", "cafebabe"),
            List.of()
        );
        assertEquals(BigInteger.ONE, result.newState.get("value"));
    }

    // ---- Surface-area sanity --------------------------------------------

    @Test
    void rejectsCtxWithWrongSighashLength() {
        AnfInterpreter.OnChainCryptoContext shortCtx =
            new AnfInterpreter.OnChainCryptoContext(new byte[20]);
        assertThrows(IllegalArgumentException.class, () ->
            AnfInterpreter.executeOnChainAuthoritative(
                sigGuardAnf(), "unlock",
                Map.of("value", BigInteger.ZERO),
                Map.of("sig", "00", "pk", "00"),
                List.of(),
                shortCtx
            )
        );
    }

    @Test
    void onChainCryptoContextFromHexAccepts32ByteHex() {
        AnfInterpreter.OnChainCryptoContext ctx =
            AnfInterpreter.OnChainCryptoContext.fromHex(repeat("11", 32));
        assertEquals(32, ctx.sighash().length);
    }

    private static String repeat(String s, int n) {
        StringBuilder sb = new StringBuilder(s.length() * n);
        for (int i = 0; i < n; i++) sb.append(s);
        return sb.toString();
    }
}

package runar.lang.sdk;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * Cross-tier BIP-143 sighash interop test (GAP-003). Loads
 * {@code conformance/sdk-bip143/fixtures.json} (TS reference, generated via
 * {@code @bsv/sdk} {@code TransactionSignature.format}) and asserts, for every
 * scenario, that this tier:
 *
 * <ol>
 *   <li>recomputes the full BIP-143 preimage byte-identically from
 *       (unsignedTxHex, inputIndex, prevScriptHex, prevValueSats) — the core
 *       node-free cross-tier correctness check;</li>
 *   <li>produces sha256d(preimage) == the fixture digestHex; and</li>
 *   <li>verifies the TS-produced sigHex against pubkeyHex over that digest.</li>
 * </ol>
 *
 * Any failure here is a cross-tier BIP-143 protocol divergence (a real
 * consensus bug). See CLAUDE.md §"Seven SDKs Must Stay in Sync".
 */
class Bip143InteropTest {

    @SuppressWarnings("unchecked")
    private static Map<String, Object> loadFixture() throws Exception {
        Path p = Paths.get(System.getProperty("user.dir"), "..", "..", "conformance", "sdk-bip143", "fixtures.json");
        String text = Files.readString(p);
        return (Map<String, Object>) Json.parse(text);
    }

    private static long asLong(Object o) {
        return ((Number) o).longValue();
    }

    private static int asInt(Object o) {
        return ((Number) o).intValue();
    }

    /** Minimal raw-tx parser: hex -> RawTx (version, inputs, outputs, locktime). */
    private static RawTx parseRawTx(String txHex) {
        byte[] b = ScriptUtils.hexToBytes(txHex);
        int[] o = {0};
        RawTx tx = new RawTx();
        tx.version = readLE32(b, o);
        long nIn = readVarInt(b, o);
        for (long i = 0; i < nIn; i++) {
            byte[] le = slice(b, o, 32);
            String prevTxid = ScriptUtils.bytesToHex(reverse(le));
            int vout = readLE32(b, o);
            long scriptLen = readVarInt(b, o);
            String scriptSig = ScriptUtils.bytesToHex(slice(b, o, (int) scriptLen));
            long seq = readLE32(b, o) & 0xffffffffL;
            tx.addInput(prevTxid, vout, scriptSig);
            tx.inputs.get(tx.inputs.size() - 1).sequence = seq;
        }
        long nOut = readVarInt(b, o);
        for (long i = 0; i < nOut; i++) {
            long sats = readLE64(b, o);
            long scriptLen = readVarInt(b, o);
            String script = ScriptUtils.bytesToHex(slice(b, o, (int) scriptLen));
            tx.addOutput(sats, script);
        }
        tx.locktime = readLE32(b, o);
        return tx;
    }

    private static byte[] slice(byte[] b, int[] o, int n) {
        byte[] out = new byte[n];
        System.arraycopy(b, o[0], out, 0, n);
        o[0] += n;
        return out;
    }

    private static byte[] reverse(byte[] in) {
        byte[] out = new byte[in.length];
        for (int i = 0; i < in.length; i++) out[i] = in[in.length - 1 - i];
        return out;
    }

    private static int readLE32(byte[] b, int[] o) {
        int v = (b[o[0]] & 0xff) | ((b[o[0] + 1] & 0xff) << 8)
            | ((b[o[0] + 2] & 0xff) << 16) | ((b[o[0] + 3] & 0xff) << 24);
        o[0] += 4;
        return v;
    }

    private static long readLE64(byte[] b, int[] o) {
        long v = 0;
        for (int i = 0; i < 8; i++) v |= (long) (b[o[0] + i] & 0xff) << (8 * i);
        o[0] += 8;
        return v;
    }

    private static long readVarInt(byte[] b, int[] o) {
        int first = b[o[0]++] & 0xff;
        if (first < 0xfd) return first;
        if (first == 0xfd) {
            long v = (b[o[0]] & 0xff) | ((b[o[0] + 1] & 0xff) << 8);
            o[0] += 2;
            return v;
        }
        if (first == 0xfe) {
            long v = readLE32(b, o) & 0xffffffffL;
            return v;
        }
        return readLE64(b, o);
    }

    @Test
    @SuppressWarnings("unchecked")
    void bip143PreimageAndSignature() throws Exception {
        Map<String, Object> fixture = loadFixture();
        List<Map<String, Object>> scenarios = (List<Map<String, Object>>) fixture.get("scenarios");
        assertFalse(scenarios.isEmpty(), "fixture has no scenarios");

        for (Map<String, Object> s : scenarios) {
            String name = (String) s.get("scenario");
            String txHex = (String) s.get("unsignedTxHex");
            int inputIndex = asInt(s.get("inputIndex"));
            String prevScriptHex = (String) s.get("prevScriptHex");
            long prevValueSats = asLong(s.get("prevValueSats"));
            String wantPreimage = (String) s.get("preimageHex");
            String wantDigest = (String) s.get("digestHex");
            String sigHex = (String) s.get("sigHex");
            String pubkeyHex = (String) s.get("pubkeyHex");
            int sighashFlags = asInt(s.get("sighashFlags"));

            // 1. Independently recompute the BIP-143 preimage under the
            //    scenario's OWN sighash flags.
            //
            //    R-206: this used to reject anything but 0x41, and every
            //    scenario in the fixture was ALL|FORKID — so the per-mode
            //    zeroing rules were implemented seven times and compared zero
            //    times.
            RawTx tx = parseRawTx(txHex);
            byte[] scriptCode = ScriptUtils.hexToBytes(prevScriptHex);
            byte[] preimage = OpPushTx.preimage(tx, inputIndex, scriptCode, prevValueSats, sighashFlags);
            String gotPreimage = ScriptUtils.bytesToHex(preimage);
            assertEquals(wantPreimage, gotPreimage, name + ": BIP-143 PREIMAGE DIVERGENCE from TS reference");

            // 2. sha256d(preimage) must equal the published digest.
            byte[] digest = Hash160.doubleSha256(preimage);
            assertEquals(wantDigest, ScriptUtils.bytesToHex(digest), name + ": sighash digest divergence");

            // 3. The TS-produced signature must verify over this tier's digest.
            byte[] sigFull = ScriptUtils.hexToBytes(sigHex);
            byte[] der = new byte[sigFull.length - 1]; // strip trailing sighash byte
            System.arraycopy(sigFull, 0, der, 0, der.length);
            ECPoint q = LocalSigner.DOMAIN.getCurve().decodePoint(ScriptUtils.hexToBytes(pubkeyHex));
            ECDSASigner verifier = new ECDSASigner();
            verifier.init(false, new ECPublicKeyParameters(q, LocalSigner.DOMAIN));
            ASN1Sequence seq = ASN1Sequence.getInstance(der);
            BigInteger r = ((ASN1Integer) seq.getObjectAt(0)).getValue();
            BigInteger sVal = ((ASN1Integer) seq.getObjectAt(1)).getValue();
            assertTrue(verifier.verifySignature(digest, r, sVal),
                name + ": TS reference signature does not verify under this tier's digest");
        }
    }
}

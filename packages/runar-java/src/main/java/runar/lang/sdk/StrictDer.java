package runar.lang.sdk;

/**
 * Strict DER (BIP66) check for an ECDSA signature — the rule a node applies
 * to every OP_CHECKSIG signature (SCRIPT_VERIFY_DERSIG). F-242.
 *
 * <p>BouncyCastle's {@code ASN1Sequence.getInstance} reads BER long-form
 * lengths and ignores SEQUENCE elements after the second, so a second byte
 * string verified as the same signature; every verifier in this SDK checks
 * this first.
 */
final class StrictDer {

    private StrictDer() {}

    /**
     * True only for the one canonical encoding of (r, s), given bare DER
     * without a sighash type byte: the SEQUENCE length covers exactly r and
     * s, both INTEGERs are non-empty, non-negative (top bit clear unless
     * behind a 0x00 pad) and minimally encoded, and nothing follows s.
     */
    static boolean isStrictDerSignature(byte[] der) {
        int n = der.length;
        if (n < 8 || n > 72) return false;
        if ((der[0] & 0xff) != 0x30 || (der[1] & 0xff) != n - 2) return false;
        int rLen = der[3] & 0xff;
        if (der[2] != 0x02 || rLen == 0 || 5 + rLen >= n) return false;
        int sLen = der[5 + rLen] & 0xff;
        if (der[4 + rLen] != 0x02 || sLen == 0 || rLen + sLen + 6 != n) return false;
        return isCanonicalInteger(der, 4, rLen) && isCanonicalInteger(der, 6 + rLen, sLen);
    }

    private static boolean isCanonicalInteger(byte[] der, int at, int len) {
        if ((der[at] & 0x80) != 0) return false;
        return !(len > 1 && der[at] == 0x00 && (der[at + 1] & 0x80) == 0);
    }
}
